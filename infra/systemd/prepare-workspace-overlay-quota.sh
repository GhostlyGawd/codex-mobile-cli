#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD

storage_root=${WORKSPACE_STORAGE_ROOT:-/srv/codex-mobile/workspaces}
expected_mount=${WORKSPACE_STORAGE_MOUNT:-/srv/codex-mobile}
overlay_root=$storage_root/.containers/overlay
volume_root=$storage_root/.containers/volumes
default_project_inode_limit=1048576

[ "$(id -u)" -eq 0 ] || {
  echo "workspace overlay quota preparation must run as root" >&2
  exit 1
}
[ "$storage_root" = "$expected_mount/workspaces" ] || {
  echo "workspace storage must use the reviewed path beneath $expected_mount" >&2
  exit 1
}
[ -d "$storage_root" ] && [ ! -L "$storage_root" ] || {
  echo "$storage_root must be an existing non-symlink directory" >&2
  exit 1
}

mount_target=$(findmnt --noheadings --output TARGET --target "$storage_root" | tr -d '[:space:]')
filesystem=$(findmnt --noheadings --output FSTYPE --target "$storage_root" | tr -d '[:space:]')
parent_options=$(findmnt --noheadings --output OPTIONS --target "$storage_root" | tr -d '[:space:]')
mount_fsroot=$(findmnt --noheadings --output FSROOT --target "$storage_root" | tr -d '[:space:]')
case "$mount_target:$mount_fsroot" in
  "$expected_mount:/"|"$storage_root:/workspaces") ;;
  *)
    echo "$storage_root must resolve to the reviewed /workspaces subtree of $expected_mount" >&2
    exit 1
    ;;
esac
[ "$filesystem" = xfs ] || {
  echo "$storage_root must reside on the dedicated XFS mount $expected_mount" >&2
  exit 1
}
case ",$parent_options," in *,pquota,*|*,prjquota,*) ;; *) echo "project quotas are not enabled" >&2; exit 1 ;; esac
case ",$parent_options," in *,nodev,*) ;; *) echo "$expected_mount must remain nodev" >&2; exit 1 ;; esac
case ",$parent_options," in *,nosuid,*) ;; *) echo "$expected_mount must remain nosuid" >&2; exit 1 ;; esac
[ -x /usr/sbin/xfs_quota ] || {
  echo "xfs_quota is required to establish the named-volume inode ceiling" >&2
  exit 1
}

# Podman 4.9 applies a volume's byte quota correctly but misclassifies a
# quota-only `inodes` driver option as a mount option. XFS default project
# limits are inherited when Podman assigns each new volume project ID, so set
# the reviewed maximum-workspace ceiling here before the engine can create one.
/usr/sbin/xfs_quota -x \
  -c "limit -p -d isoft=$default_project_inode_limit ihard=$default_project_inode_limit" \
  "$expected_mount"
default_inode_record=$(/usr/sbin/xfs_quota -x \
  -c 'quota -p -i -n -N -v 0' "$expected_mount")
printf '%s\n' "$default_inode_record" | awk \
  -v expected="$default_project_inode_limit" '
    NF >= 4 && $3 == expected && $4 == expected { found = 1 }
    END { exit(found ? 0 : 1) }
  ' || {
    echo "XFS default project inode ceiling is not enforced" >&2
    exit 1
  }

install -d -o root -g root -m 0700 "$storage_root/.containers"
install -d -o root -g root -m 0700 "$overlay_root"
install -d -o root -g root -m 0700 "$volume_root"
[ ! -L "$storage_root/.containers" ] &&
  [ ! -L "$overlay_root" ] &&
  [ ! -L "$volume_root" ] || {
  echo "workspace overlay quota paths must not be symlinks" >&2
  exit 1
}
[ "$(stat -c '%u:%g:%a' "$storage_root/.containers")" = 0:0:700 ] &&
  [ "$(stat -c '%u:%g:%a' "$overlay_root")" = 0:0:700 ] &&
  [ "$(stat -c '%u:%g:%a' "$volume_root")" = 0:0:700 ] || {
    echo "workspace overlay quota paths must be root:root mode 0700" >&2
    exit 1
  }

parent_device=$(findmnt --noheadings --output MAJ:MIN --target "$expected_mount" | tr -d '[:space:]')
for quota_root in "$overlay_root" "$volume_root"; do
  created=false
  remount_required=false
  expected_fsroot=${quota_root#"$expected_mount"}

  # containers/storage removes its temporary backing-device mount when a
  # short-lived Podman CLI exits. Restore the reviewed self-bind when it is
  # missing, but reuse a valid topmost exact bind instead of stacking another
  # mount on every preparation call.
  if quota_records=$(findmnt --raw --noheadings \
    --output TARGET,FSTYPE,OPTIONS,FSROOT,MAJ:MIN \
    --mountpoint "$quota_root" 2>/dev/null); then
    quota_record=$(printf '%s\n' "$quota_records" | tail -n 1)
    quota_extra=
    IFS=' ' read -r \
      quota_target quota_filesystem quota_options quota_fsroot quota_device quota_extra <<EOF
$quota_record
EOF
    [ -n "$quota_target" ] &&
      [ -n "$quota_filesystem" ] &&
      [ -n "$quota_options" ] &&
      [ -n "$quota_fsroot" ] &&
      [ -n "$quota_device" ] &&
      [ -z "$quota_extra" ] || {
      echo "workspace quota exception has an invalid mount record: $quota_root" >&2
      exit 1
    }
    [ "$quota_target" = "$quota_root" ] &&
      [ "$quota_filesystem" = xfs ] &&
      [ "$quota_fsroot" = "$expected_fsroot" ] &&
      [ "$quota_device" = "$parent_device" ] || {
        echo "workspace quota exception is not the exact reviewed self-bind: $quota_root" >&2
        exit 1
      }
    case ",$quota_options," in
      *,nodev,*)
        echo "$quota_root must permit its private backing device" >&2
        exit 1
        ;;
    esac
    case ",$quota_options," in
      *,nosuid,*) ;;
      *)
        echo "$quota_root must remain nosuid" >&2
        exit 1
        ;;
    esac
    case ",$quota_options," in
      *,rw,*) ;;
      *,ro,*) remount_required=true ;;
      *)
        echo "$quota_root must be explicitly read-write or read-only" >&2
        exit 1
        ;;
    esac
  else
    mount --bind "$quota_root" "$quota_root"
    created=true
    remount_required=true
  fi

  if [ "$remount_required" = true ] &&
    ! mount -o remount,bind,rw,dev,nosuid "$quota_root"; then
    [ "$created" = false ] || umount "$quota_root"
    exit 1
  fi

  # systemd's ReadWritePaths may add a lower bind of /workspaces while the
  # reviewed dev-capable self-bind remains the topmost exact mount. Inspect
  # that topmost record instead of concatenating both layers.
  quota_record=$(findmnt --raw --noheadings \
    --output TARGET,FSTYPE,OPTIONS,FSROOT,MAJ:MIN \
    --mountpoint "$quota_root" | tail -n 1)
  quota_extra=
  IFS=' ' read -r \
    quota_target quota_filesystem quota_options quota_fsroot quota_device quota_extra <<EOF
$quota_record
EOF
  [ -n "$quota_target" ] &&
    [ -n "$quota_filesystem" ] &&
    [ -n "$quota_options" ] &&
    [ -n "$quota_fsroot" ] &&
    [ -n "$quota_device" ] &&
    [ -z "$quota_extra" ] || {
    echo "workspace quota exception has an invalid mount record: $quota_root" >&2
    exit 1
  }
  [ "$quota_target" = "$quota_root" ] &&
    [ "$quota_filesystem" = xfs ] &&
    [ "$quota_fsroot" = "$expected_fsroot" ] &&
    [ "$quota_device" = "$parent_device" ] || {
      echo "workspace quota exception is not the exact reviewed self-bind: $quota_root" >&2
      exit 1
    }
  case ",$quota_options," in *,rw,*) ;; *) echo "$quota_root must remain read-write" >&2; exit 1 ;; esac
  case ",$quota_options," in *,nodev,*) echo "$quota_root must permit its private backing device" >&2; exit 1 ;; esac
  case ",$quota_options," in *,nosuid,*) ;; *) echo "$quota_root must remain nosuid" >&2; exit 1 ;; esac
done

exit 0
