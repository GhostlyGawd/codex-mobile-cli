terraform {
  # Coder v2.34.6 embeds Terraform 1.14.5 and rejects >=1.14.9. Pinning
  # Coder's exact bundled version keeps external-provisioner behavior stable.
  required_version = "= 1.14.5"

  required_providers {
    coder = {
      source  = "coder/coder"
      version = "= 2.18.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "= 4.5.0"
    }
  }
}

# The external provisioner supplies DOCKER_HOST for the dedicated private
# rootful Podman API. The provisioner remains an unprivileged account, and the
# engine socket is never mounted into Coder or a workspace container.
provider "coder" {}
provider "docker" {}

variable "deployment_profile" {
  description = "Explicit host profile. The owner-PC WSL profile truthfully omits unavailable AppArmor while retaining every other runtime boundary."
  type        = string

  validation {
    condition     = contains(["owner_pc_beta", "fixed_price_vps"], var.deployment_profile)
    error_message = "deployment_profile must be owner_pc_beta or fixed_price_vps."
  }
}

variable "workspace_base_image" {
  description = "Locally built, non-root fallback image. It is never pulled from a paid registry."
  type        = string
  default     = "localhost/codex-mobile/workspace-base:2026-07-15"
}

variable "envbuilder_image" {
  description = "Locally source-built EnvBuilder derivative containing the trusted helper volume seed."
  type        = string
  default     = "localhost/codex-mobile/envbuilder:1.3.0-codex-mobile.1"
}

variable "workspace_apparmor_profile" {
  description = "AppArmor profile created and maintained by the dedicated Podman runtime."
  type        = string
  default     = "container-default"
}

variable "workspace_io_device" {
  description = "Exact administrator-verified block-device source backing /srv/codex-mobile. Supplied at template push; never guessed by the template."
  type        = string

  validation {
    condition     = can(regex("^/dev/[A-Za-z0-9._/+:-]+$", var.workspace_io_device))
    error_message = "workspace_io_device must be an explicit normalized /dev path verified against the data mount."
  }
}

variable "coder_control_address" {
  description = "Operator-verified RFC1918 address of the private Coder listener. Workspace traffic reaches only this address through an immutable relay."
  type        = string

  validation {
    condition = can(cidrhost("${var.coder_control_address}/32", 0)) && (
      startswith(var.coder_control_address, "10.") ||
      can(regex("^172\\.(1[6-9]|2[0-9]|3[01])\\.", var.coder_control_address)) ||
      startswith(var.coder_control_address, "192.168.")
    )
    error_message = "coder_control_address must be a literal RFC1918 IPv4 address."
  }
}

variable "coder_control_port" {
  description = "Operator-verified TCP port of the private Coder listener."
  type        = number

  validation {
    condition     = var.coder_control_port >= 1 && var.coder_control_port <= 65535 && floor(var.coder_control_port) == var.coder_control_port
    error_message = "coder_control_port must be an integer from 1 through 65535."
  }
}

data "coder_provisioner" "current" {}
data "coder_workspace" "current" {}

# This fixed network is created and validated by the root-owned workspace
# runtime service. Only immutable relay containers attach to it; repository
# code never receives this network or the Podman socket.
data "docker_network" "workspace_control" {
  name = "codex-mobile-control"
}

data "coder_parameter" "workspace_mode" {
  name         = "workspace_mode"
  display_name = "Workspace environment"
  description  = "Plain is the safe default. EnvBuilder executes approved repository Dev Container configuration."
  type         = "string"
  default      = "plain"
  mutable      = true
  order        = 1

  option {
    name        = "Plain safe workspace"
    value       = "plain"
    description = "Use the maintained local image; do not execute Dev Container configuration."
  }

  option {
    name        = "Approved Dev Container (EnvBuilder)"
    value       = "approved-envbuilder"
    description = "Execute the selected Dev Container only after an application trust decision."
  }
}

data "coder_parameter" "setup_approval_id" {
  name         = "setup_approval_id"
  display_name = "Setup approval receipt"
  description  = "Opaque control-plane receipt. Required for EnvBuilder mode; not a secret."
  type         = "string"
  default      = ""
  mutable      = true
  order        = 2

  validation {
    regex = "^$|^approval_[a-f0-9]{32}$"
    error = "Approval receipt must be empty or approval_ followed by 32 lowercase hexadecimal characters."
  }
}

data "coder_parameter" "devcontainer_dir" {
  name         = "devcontainer_dir"
  display_name = "Dev Container directory"
  description  = "Exact standard directory persisted by the control plane before the plain bootstrap."
  type         = "string"
  default      = ".devcontainer"
  mutable      = true
  order        = 3

  validation {
    regex = "^\\.$|^\\.devcontainer$"
    error = "Use '.' for .devcontainer.json or '.devcontainer' for .devcontainer/devcontainer.json."
  }
}

data "coder_parameter" "allow_egress" {
  name         = "allow_egress"
  display_name = "Approved outbound network"
  description  = "Balanced-mode default. The control plane disables it for suspended workspaces or operations requiring offline execution."
  type         = "bool"
  default      = true
  mutable      = true
  order        = 4
}

data "coder_parameter" "cpu_millis" {
  name         = "cpu_millis"
  display_name = "CPU quota (millicores)"
  description  = "Assigned by the application equal-share admission controller."
  type         = "number"
  default      = 500
  mutable      = true
  order        = 10

  validation {
    min   = 500
    max   = 8000
    error = "CPU quota must remain between {min} and {max} millicores."
  }
}

data "coder_parameter" "memory_mb" {
  name         = "memory_mb"
  display_name = "Memory quota (MiB)"
  description  = "Assigned by the application equal-share admission controller."
  type         = "number"
  default      = 1536
  mutable      = true
  order        = 11

  validation {
    min   = 1536
    max   = 18432
    error = "Memory quota must remain between {min} and {max} MiB."
  }
}

data "coder_parameter" "disk_gib" {
  name         = "disk_gib"
  display_name = "Persistent disk quota (GiB)"
  description  = "Immutable XFS project quota assigned by the application at workspace creation."
  type         = "number"
  default      = 12
  mutable      = false
  order        = 12

  validation {
    min   = 8
    max   = 16
    error = "Persistent disk quota must remain between {min} and {max} GiB."
  }
}

data "coder_parameter" "pids_limit" {
  name         = "pids_limit"
  display_name = "Process limit"
  description  = "Fixed to the dedicated Podman runtime's creation-time cgroup policy."
  type         = "number"
  default      = 512
  mutable      = false
  order        = 13

  validation {
    min   = 512
    max   = 512
    error = "The dedicated workspace runtime enforces exactly {min} processes per container."
  }
}

locals {
  workspace_key             = substr(replace(data.coder_workspace.current.id, "-", ""), 0, 24)
  container_name            = "cm-ws-${local.workspace_key}"
  workspace_folder          = "/workspaces/repository"
  envbuilder_approved       = data.coder_parameter.workspace_mode.value == "approved-envbuilder"
  approval_receipt_ok       = can(regex("^approval_[a-f0-9]{32}$", data.coder_parameter.setup_approval_id.value))
  selected_devcontainer_dir = "${local.workspace_folder}/${data.coder_parameter.devcontainer_dir.value}"
  workspace_helper_sha256 = {
    amd64 = "ba7080f880206d90e05d751245c3635b9bdcbcbbc6152d61c3ec4221fd5bdf14"
    arm64 = "3042240a601842f35233e383835a3e40aef6b05640b44f723bafefb133fdf9aa"
  }[data.coder_provisioner.current.arch]
  workspace_codex_package_sha256 = {
    amd64 = "71a28d362c96ac9829bf8203a2c71be451aeb726adb843167fdaf0eae8fe7dd9"
    arm64 = "54f79a05aba6f9abf8ef988abcae8bf2fcefba20beb549b4ff2b3acdb2cb6f54"
  }[data.coder_provisioner.current.arch]
  workspace_helper_path = "/opt/codex-mobile-helper/codex-mobile-workspace-helper"
  workspace_disk_bytes  = data.coder_parameter.disk_gib.value * 1073741824
  workspace_inode_limit = 1048576
  workspace_userns_mode = var.deployment_profile == "owner_pc_beta" ? "auto:size=65536" : "private"
  workspace_read_bps    = 67108864
  workspace_write_bps   = 33554432
  workspace_read_iops   = 2000
  workspace_write_iops  = 1000
  coder_relay_url       = "http://cm-coder-control:7080"
  workspace_security_opts = concat(
    ["no-new-privileges:true"],
    var.deployment_profile == "fixed_price_vps" ? ["apparmor=${var.workspace_apparmor_profile}"] : [],
  )
  coder_agent_init_script = replace(
    coder_agent.main.init_script,
    data.coder_workspace.current.access_url,
    local.coder_relay_url,
  )

  common_labels = {
    "com.codex-mobile.managed"        = "true"
    "com.codex-mobile.workspace-id"   = data.coder_workspace.current.id
    "com.codex-mobile.workspace-name" = data.coder_workspace.current.name
    "com.codex-mobile.pids-limit"     = tostring(data.coder_parameter.pids_limit.value)
    "com.codex-mobile.cpu-millis"     = tostring(data.coder_parameter.cpu_millis.value)
    "com.codex-mobile.memory-mib"     = tostring(data.coder_parameter.memory_mb.value)
    "com.codex-mobile.profile"        = var.deployment_profile
  }

  envbuilder_environment = [
    "CODER_AGENT_TOKEN=${coder_agent.main.token}",
    "CODER_AGENT_URL=${local.coder_relay_url}",
    "ENVBUILDER_INIT_SCRIPT=${local.coder_agent_init_script}",
    "ENVBUILDER_WORKSPACE_FOLDER=${local.workspace_folder}",
    "ENVBUILDER_DEVCONTAINER_DIR=${local.selected_devcontainer_dir}",
    "ENVBUILDER_FALLBACK_IMAGE=${var.workspace_base_image}",
    "ENVBUILDER_LAYER_CACHE_DIR=/workspaces/.codex-mobile/envbuilder-cache",
    # Keep the read-only helper mount outside EnvBuilder's snapshot/delete
    # operations. Specifying this option replaces upstream defaults, so retain
    # all three EnvBuilder 1.3.0 default ignore paths as well.
    "ENVBUILDER_IGNORE_PATHS=/var/run,/product_uuid,/product_name,/opt/codex-mobile-helper",
    "ENVBUILDER_EXIT_ON_BUILD_FAILURE=true",
    "ENVBUILDER_FORCE_SAFE=false",
    "ENVBUILDER_INSECURE=false",
    "ENVBUILDER_PUSH_IMAGE=false",
    "ENVBUILDER_REMOTE_REPO_BUILD_MODE=false",
    # Reject root as the final interactive identity. EnvBuilder runs this fixed
    # operator script after building and before it drops to the target user.
    "ENVBUILDER_SETUP_SCRIPT=test -x ${local.workspace_helper_path}; if [ \"$${TARGET_USER:-root}\" = root ]; then echo 'Dev Container must define a non-root remoteUser/containerUser' >&2; exit 1; fi; printf 'TARGET_USER=%s\\n' \"$${TARGET_USER}\" >> \"$${ENVBUILDER_ENV}\"",
  ]
}

resource "docker_image" "workspace_base" {
  name         = var.workspace_base_image
  keep_locally = true
}

resource "docker_image" "envbuilder" {
  name         = var.envbuilder_image
  keep_locally = true
}

# Podman 4.9.3 reuses one XFS project ID across local volumes. The owner-PC
# profile therefore serializes the sole quota-bearing workspace volume before
# the Docker provider can create it. On destroy, Terraform removes the volume
# first and releases the matching lease only after that deletion succeeds.
resource "terraform_data" "owner_pc_volume_lease" {
  count = var.deployment_profile == "owner_pc_beta" ? 1 : 0

  input = {
    workspace_id   = data.coder_workspace.current.id
    workspace_name = data.coder_workspace.current.name
  }

  provisioner "local-exec" {
    command = "/usr/local/libexec/codex-mobile/owner-pc-workspace-volume-gate claim --workspace-id \"$WORKSPACE_ID\" --workspace-name \"$WORKSPACE_NAME\""
    environment = {
      WORKSPACE_ID   = self.input.workspace_id
      WORKSPACE_NAME = self.input.workspace_name
    }
  }

  provisioner "local-exec" {
    when    = destroy
    command = "/usr/local/libexec/codex-mobile/owner-pc-workspace-volume-gate release --workspace-id \"$WORKSPACE_ID\" --workspace-name \"$WORKSPACE_NAME\""
    environment = {
      WORKSPACE_ID   = self.input.workspace_id
      WORKSPACE_NAME = self.input.workspace_name
    }
  }
}

resource "docker_volume" "workspace" {
  name = "cm-workspace-v2-${local.workspace_key}"

  # Podman interprets these local-volume options as XFS project quotas. Volume
  # creation fails when the graphroot is not on XFS mounted with pquota/prjquota.
  # The root-owned runtime establishes the XFS default project inode ceiling
  # before Podman starts. Podman 4.9 otherwise misclassifies a quota-only
  # `inodes` option as a mount option. The application never changes disk_gib
  # after creation, and ignore_changes prevents Terraform from replacing
  # persistent data during later rebalances.
  driver_opts = {
    o = "size=${local.workspace_disk_bytes}"
  }

  dynamic "labels" {
    for_each = merge(local.common_labels, {
      "com.codex-mobile.volume-role" = "workspace-data"
      "com.codex-mobile.disk-budget" = tostring(local.workspace_disk_bytes)
    })
    content {
      label = labels.key
      value = labels.value
    }
  }

  lifecycle {
    ignore_changes = all
  }

  depends_on = [terraform_data.owner_pc_volume_lease]
}

# Docker/Podman copies the trusted image contents into this empty named volume
# on its first mount. Both workspace modes then mount it read-only. Including
# the architecture-specific binary checksum in the volume name makes helper
# updates create a fresh volume instead of retaining stale bytes.
resource "docker_volume" "workspace_helper" {
  name = "cm-helper-${local.workspace_key}-${substr(local.workspace_helper_sha256, 0, 16)}-${substr(local.workspace_codex_package_sha256, 0, 8)}"

  dynamic "labels" {
    for_each = merge(local.common_labels, {
      "com.codex-mobile.workspace-helper-sha256" = local.workspace_helper_sha256
      "com.codex-mobile.codex-package-sha256"    = local.workspace_codex_package_sha256
      "com.codex-mobile.codex-version"           = "0.145.0"
      "com.codex-mobile.volume-role"             = "trusted-helper"
    })
    content {
      label = labels.key
      value = labels.value
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "docker_network" "workspace" {
  count    = data.coder_workspace.current.start_count
  name     = "cm-net-${local.workspace_key}"
  driver   = "bridge"
  internal = true

  dynamic "labels" {
    for_each = local.common_labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

# Balanced and Full Access add a distinct outbound bridge. Safe Mode has no
# route beyond its internal workspace bridge; Coder control traffic continues
# through the narrow relay below and is not treated as general egress.
resource "docker_network" "egress" {
  count  = data.coder_workspace.current.start_count * (data.coder_parameter.allow_egress.value ? 1 : 0)
  name   = "cm-egress-${local.workspace_key}"
  driver = "bridge"

  dynamic "labels" {
    for_each = local.common_labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

# The relay is an application-layer TCP forwarder, not a router. It owns no
# token, volume, host path, device, capability, or engine socket and has a
# fixed target supplied only when the owner imports the trusted template.
resource "docker_container" "coder_relay" {
  count = data.coder_workspace.current.start_count

  name         = "cm-relay-${local.workspace_key}"
  hostname     = "cm-coder-control"
  image        = docker_image.workspace_base.image_id
  user         = "1000:1000"
  command      = ["/usr/bin/socat", "TCP4-LISTEN:7080,bind=0.0.0.0,reuseaddr,fork", "TCP4:${var.coder_control_address}:${var.coder_control_port},connect-timeout=10"]
  must_run     = true
  restart      = "no"
  read_only    = true
  userns_mode  = local.workspace_userns_mode
  memory       = 64
  memory_swap  = 64
  cpu_period   = 100000
  cpu_quota    = 10000
  shm_size     = 16
  stop_timeout = 10

  networks_advanced {
    name    = docker_network.workspace[0].name
    aliases = ["cm-coder-control"]
  }

  networks_advanced {
    name = data.docker_network.workspace_control.name
  }

  capabilities {
    add  = []
    drop = ["ALL"]
  }

  security_opts = local.workspace_security_opts

  tmpfs = {
    "/tmp" = "rw,nosuid,nodev,noexec,size=8388608,uid=1000,gid=1000,mode=0700"
  }

  ulimit {
    name = "nofile"
    soft = 256
    hard = 512
  }

  dynamic "labels" {
    for_each = {
      "com.codex-mobile.container-role"             = "workspace-relay"
      "com.codex-mobile.control-relay-workspace-id" = data.coder_workspace.current.id
      "com.codex-mobile.workspace-id"               = data.coder_workspace.current.id
      "com.codex-mobile.workspace-name"             = data.coder_workspace.current.name
      "com.codex-mobile.profile"                    = var.deployment_profile
      "com.codex-mobile.pids-limit"                 = "512"
      "com.codex-mobile.cpu-millis"                 = "100"
      "com.codex-mobile.memory-mib"                 = "64"
    }
    content {
      label = labels.key
      value = labels.value
    }
  }

  log_driver = "local"
  log_opts = {
    "max-size" = "1m"
    "max-file" = "2"
  }
}

resource "coder_agent" "main" {
  arch = data.coder_provisioner.current.arch
  os   = "linux"

  # This key can register and operate the agent, but cannot call user-data APIs.
  # Repository access is brokered by the control plane with a short-lived token.
  api_key_scope = "no_user_data"

  display_apps {
    port_forwarding_helper = false
    ssh_helper             = false
    vscode                 = false
    vscode_insiders        = false
    web_terminal           = false
  }

  env = {
    HOME       = "/workspaces/.home"
    CODEX_HOME = "/workspaces/.codex-home"
    PATH       = "/opt/codex-mobile-helper:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    TERM       = "xterm-256color"
  }

  startup_script = <<-EOT
    set -eu
    umask 077
    mkdir -p /workspaces/repository /workspaces/.home /workspaces/.codex-home /workspaces/.codex-mobile
    test -x "$(command -v tmux)"
    test -x ${local.workspace_helper_path}
    test "$(command -v codex)" = /opt/codex-mobile-helper/codex
    test -x /opt/codex-mobile-helper/codex-real
  EOT

  metadata {
    display_name = "CPU"
    key          = "cpu"
    script       = "coder stat cpu"
    interval     = 10
    timeout      = 2
  }

  metadata {
    display_name = "Memory"
    key          = "memory"
    script       = "coder stat mem"
    interval     = 10
    timeout      = 2
  }

  metadata {
    display_name = "Workspace disk"
    key          = "disk"
    script       = "coder stat disk --path /workspaces"
    interval     = 60
    timeout      = 2
  }
}

# Safe default: a non-root, read-only-rootfs container with every Linux
# capability dropped. Only its private persistent volume is writable.
resource "docker_container" "plain" {
  count = data.coder_workspace.current.start_count * (local.envbuilder_approved ? 0 : 1)

  name        = local.container_name
  hostname    = data.coder_workspace.current.name
  image       = docker_image.workspace_base.image_id
  user        = "1000:1000"
  working_dir = local.workspace_folder
  command     = ["/bin/sh", "-c", local.coder_agent_init_script]
  env = [
    "CODER_AGENT_TOKEN=${coder_agent.main.token}",
    "CODER_AGENT_URL=${local.coder_relay_url}",
  ]
  must_run     = true
  restart      = "no"
  read_only    = true
  userns_mode  = local.workspace_userns_mode
  memory       = data.coder_parameter.memory_mb.value
  memory_swap  = data.coder_parameter.memory_mb.value
  cpu_period   = 100000
  cpu_quota    = data.coder_parameter.cpu_millis.value * 100
  shm_size     = 256
  stop_timeout = 30

  networks_advanced {
    name = docker_network.workspace[0].name
  }

  dynamic "networks_advanced" {
    for_each = docker_network.egress
    content {
      name = networks_advanced.value.name
    }
  }

  device_read_bps {
    path = var.workspace_io_device
    rate = local.workspace_read_bps
  }

  device_write_bps {
    path = var.workspace_io_device
    rate = local.workspace_write_bps
  }

  device_read_iops {
    path = var.workspace_io_device
    rate = local.workspace_read_iops
  }

  device_write_iops {
    path = var.workspace_io_device
    rate = local.workspace_write_iops
  }

  capabilities {
    add  = []
    drop = ["ALL"]
  }

  security_opts = local.workspace_security_opts

  lifecycle {
    precondition {
      condition = var.deployment_profile != "owner_pc_beta" || (
        data.coder_parameter.cpu_millis.value == 2000 &&
        data.coder_parameter.memory_mb.value == 2048 &&
        data.coder_parameter.pids_limit.value == 512
      )
      error_message = "owner_pc_beta requires exactly 2000m CPU, 2048 MiB memory, and 512 processes."
    }
  }

  volumes {
    container_path = "/workspaces"
    volume_name    = docker_volume.workspace.name
    read_only      = false
  }

  volumes {
    container_path = "/opt/codex-mobile-helper"
    volume_name    = docker_volume.workspace_helper.name
    read_only      = true
  }

  tmpfs = {
    "/tmp"                      = "rw,nosuid,nodev,size=268435456,uid=1000,gid=1000"
    "/codex-mobile-attachments" = "rw,nosuid,nodev,noexec,size=67108864,uid=1000,gid=1000,mode=0700"
  }

  ulimit {
    name = "nofile"
    soft = 4096
    hard = 8192
  }

  dynamic "labels" {
    for_each = merge(local.common_labels, {
      "com.codex-mobile.container-role" = "workspace-workload"
    })
    content {
      label = labels.key
      value = labels.value
    }
  }

  log_driver = "local"
  log_opts = {
    "max-size" = "10m"
    "max-file" = "3"
  }

  depends_on = [docker_container.coder_relay]
}

# Approval-gated compatibility mode. EnvBuilder itself needs a small set of
# filesystem/user-switch capabilities while transforming the image. They exist
# only inside Podman's private user namespace; networking, raw sockets,
# devices, host namespaces, host paths, and the engine API remain unavailable.
resource "docker_container" "envbuilder" {
  count = data.coder_workspace.current.start_count * (local.envbuilder_approved ? 1 : 0)

  name         = local.container_name
  hostname     = data.coder_workspace.current.name
  image        = docker_image.envbuilder.image_id
  env          = local.envbuilder_environment
  must_run     = true
  restart      = "no"
  read_only    = false
  userns_mode  = local.workspace_userns_mode
  memory       = data.coder_parameter.memory_mb.value
  memory_swap  = data.coder_parameter.memory_mb.value
  cpu_period   = 100000
  cpu_quota    = data.coder_parameter.cpu_millis.value * 100
  shm_size     = 256
  stop_timeout = 30


  networks_advanced {
    name = docker_network.workspace[0].name
  }

  dynamic "networks_advanced" {
    for_each = docker_network.egress
    content {
      name = networks_advanced.value.name
    }
  }
  # EnvBuilder intentionally needs a writable root while it constructs the
  # approved Dev Container. Bound that ephemeral overlay independently of the
  # persistent /workspaces XFS volume; unsupported oversized builds fail
  # closed instead of consuming the host graphroot.
  storage_opts = {
    size   = "4G"
    inodes = "262144"
  }

  device_read_bps {
    path = var.workspace_io_device
    rate = local.workspace_read_bps
  }

  device_write_bps {
    path = var.workspace_io_device
    rate = local.workspace_write_bps
  }

  device_read_iops {
    path = var.workspace_io_device
    rate = local.workspace_read_iops
  }

  device_write_iops {
    path = var.workspace_io_device
    rate = local.workspace_write_iops
  }

  capabilities {
    add = [
      "CHOWN",
      "DAC_OVERRIDE",
      "FOWNER",
      "FSETID",
      "SETFCAP",
      "SETGID",
      "SETUID",
      "SYS_CHROOT",
    ]
    drop = ["ALL"]
  }

  security_opts = local.workspace_security_opts

  lifecycle {
    precondition {
      condition = var.deployment_profile != "owner_pc_beta" || (
        data.coder_parameter.cpu_millis.value == 2000 &&
        data.coder_parameter.memory_mb.value == 2048 &&
        data.coder_parameter.pids_limit.value == 512
      )
      error_message = "owner_pc_beta requires exactly 2000m CPU, 2048 MiB memory, and 512 processes."
    }
    precondition {
      condition     = local.approval_receipt_ok
      error_message = "EnvBuilder mode requires a valid control-plane setup approval receipt."
    }
  }

  volumes {
    container_path = "/workspaces"
    volume_name    = docker_volume.workspace.name
    read_only      = false
  }


  volumes {
    container_path = "/opt/codex-mobile-helper"
    volume_name    = docker_volume.workspace_helper.name
    read_only      = true
  }

  tmpfs = {
    "/tmp"                      = "rw,nosuid,nodev,size=536870912"
    "/run"                      = "rw,nosuid,nodev,noexec,size=67108864"
    "/codex-mobile-attachments" = "rw,nosuid,nodev,noexec,size=67108864,uid=1000,gid=1000,mode=0700"
  }

  ulimit {
    name = "nofile"
    soft = 4096
    hard = 8192
  }

  dynamic "labels" {
    for_each = merge(local.common_labels, {
      "com.codex-mobile.container-role"        = "workspace-workload"
      "com.codex-mobile.devcontainer-approved" = data.coder_parameter.setup_approval_id.value
      "com.codex-mobile.envbuilder-version"    = "1.3.0-codex-mobile.1"
    })
    content {
      label = labels.key
      value = labels.value
    }
  }

  log_driver = "local"
  log_opts = {
    "max-size" = "10m"
    "max-file" = "3"
  }

  depends_on = [docker_container.coder_relay]
}

resource "coder_metadata" "workspace" {
  count       = data.coder_workspace.current.start_count
  resource_id = local.envbuilder_approved ? docker_container.envbuilder[0].id : docker_container.plain[0].id

  item {
    key   = "environment"
    value = data.coder_parameter.workspace_mode.value
  }
  item {
    key   = "egress approved"
    value = tostring(data.coder_parameter.allow_egress.value)
  }
  item {
    key   = "private Podman runtime"
    value = "root-owned engine; unprivileged provisioner; no workspace socket"
  }
  item {
    key   = "persistent disk quota"
    value = "${data.coder_parameter.disk_gib.value} GiB / ${local.workspace_inode_limit} inodes"
  }
}
