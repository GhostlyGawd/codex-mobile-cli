package workspacehelper

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxProcEntries          = 4096
	maxProcFDs              = 65536
	maxProcCommandLineBytes = 4096

	trustedTmuxPath            = "/usr/bin/tmux"
	trustedWorkspaceHelperPath = trustedCodexDirectory + "/codex-mobile-workspace-helper"
)

// RuntimeActivity intentionally exposes counts rather than process names or
// command lines. Those values are untrusted workspace content and do not need
// to cross the helper boundary to make a lifecycle decision.
type RuntimeActivity struct {
	Busy               bool   `json:"busy"`
	ActiveProcessCount int    `json:"active_process_count"`
	ListeningPortCount int    `json:"listening_port_count"`
	Reason             string `json:"reason,omitempty"`
}

type procInfo struct {
	pid  int
	ppid int
	// name is parsed to reject malformed status records, but is deliberately
	// never used as process identity: an untrusted process can change its comm.
	name  string
	state byte
}

func (h *Helper) runtimeActivityProbe() Response {
	activity, err := inspectRuntimeActivity("/proc", os.Getpid())
	if err != nil {
		return failure("precondition", "Workspace runtime activity could not be inspected.")
	}
	return Response{Version: Version, OK: true, RuntimeActivity: &activity}
}

func inspectRuntimeActivity(procRoot string, selfPID int) (RuntimeActivity, error) {
	return inspectRuntimeActivityWithReadlink(procRoot, selfPID, os.Readlink)
}

func inspectRuntimeActivityWithReadlink(procRoot string, selfPID int, readlink func(string) (string, error)) (RuntimeActivity, error) {
	if readlink == nil {
		return RuntimeActivity{}, errors.New("process link reader is unavailable")
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return RuntimeActivity{}, err
	}
	if len(entries) > maxProcEntries*2 {
		return RuntimeActivity{}, errors.New("process table exceeds inspection limit")
	}
	processes := make(map[int]procInfo)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if len(processes) >= maxProcEntries {
			return RuntimeActivity{}, errors.New("process table exceeds inspection limit")
		}
		info, err := readProcStatus(filepath.Join(procRoot, entry.Name(), "status"), pid)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue
		}
		if err != nil {
			return RuntimeActivity{}, err
		}
		processes[pid] = info
	}

	ignored := make(map[int]bool)
	for pid := selfPID; pid > 0 && !ignored[pid]; {
		ignored[pid] = true
		info, ok := processes[pid]
		if !ok {
			break
		}
		pid = info.ppid
	}

	listeners, err := listeningSocketInodes(procRoot)
	if err != nil {
		return RuntimeActivity{}, err
	}
	active := 0
	ownedListeners := make(map[string]struct{})
	totalFDs := 0
	for pid, info := range processes {
		if ignored[pid] || info.state == 'Z' || info.state == 'X' {
			continue
		}
		// A process name is attacker-controlled. Exclude only quiescent processes
		// whose immutable executable and managed tmux ancestry prove that they are
		// part of the app's terminal infrastructure. Any inspection ambiguity is
		// deliberately fail-busy so work cannot be suspended by hiding its name.
		if !managedIdleRuntimeProcess(procRoot, info, processes, readlink) {
			active++
		}
		fdEntries, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(pid), "fd"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue
		}
		if err != nil {
			return RuntimeActivity{}, err
		}
		totalFDs += len(fdEntries)
		if totalFDs > maxProcFDs {
			return RuntimeActivity{}, errors.New("process descriptors exceed inspection limit")
		}
		for _, fd := range fdEntries {
			target, err := readlink(filepath.Join(procRoot, strconv.Itoa(pid), "fd", fd.Name()))
			if err != nil {
				continue
			}
			inode := socketInode(target)
			if _, ok := listeners[inode]; ok {
				ownedListeners[inode] = struct{}{}
			}
		}
	}

	activity := RuntimeActivity{
		ActiveProcessCount: active,
		ListeningPortCount: len(ownedListeners),
	}
	activity.Busy = activity.ActiveProcessCount > 0 || activity.ListeningPortCount > 0
	if activity.ListeningPortCount > 0 {
		activity.Reason = "listening-development-service"
	} else if activity.ActiveProcessCount > 0 {
		activity.Reason = "foreground-or-background-process"
	} else {
		activity.Reason = "inactive"
	}
	return activity, nil
}

func managedIdleRuntimeProcess(procRoot string, info procInfo, processes map[int]procInfo, readlink func(string) (string, error)) bool {
	if info.state == 'R' || info.state == 'D' {
		return false
	}
	executable, err := procExecutable(procRoot, info.pid, readlink)
	if err != nil {
		return false
	}
	switch executable {
	case trustedTmuxPath:
		// The trusted tmux server itself is infrastructure. TCP listeners are
		// still inspected independently and always make the runtime busy.
		return true
	case "/bin/bash", "/usr/bin/bash":
		return processHasExecutable(procRoot, processes, info.ppid, trustedTmuxPath, readlink) &&
			managedLoginShell(procRoot, info.pid)
	case trustedWorkspaceHelperPath:
		return processHasExecutable(procRoot, processes, info.ppid, trustedTmuxPath, readlink)
	case TrustedCodexPath:
		parent, ok := processes[info.ppid]
		return ok && processHasExecutable(procRoot, processes, parent.pid, trustedWorkspaceHelperPath, readlink) &&
			processHasExecutable(procRoot, processes, parent.ppid, trustedTmuxPath, readlink)
	default:
		return false
	}
}

func processHasExecutable(procRoot string, processes map[int]procInfo, pid int, expected string, readlink func(string) (string, error)) bool {
	info, ok := processes[pid]
	if !ok || info.state == 'Z' || info.state == 'X' {
		return false
	}
	executable, err := procExecutable(procRoot, pid, readlink)
	return err == nil && executable == expected
}

func procExecutable(procRoot string, pid int, readlink func(string) (string, error)) (string, error) {
	target, err := readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", err
	}
	// /proc exposes Linux paths even when fixtures are evaluated on another
	// host OS. Deleted or non-canonical targets are never trusted as baseline.
	if !strings.HasPrefix(target, "/") || path.Clean(target) != target || strings.HasSuffix(target, " (deleted)") {
		return "", errors.New("process executable is not trusted")
	}
	return target, nil
}

func managedLoginShell(procRoot string, pid int) bool {
	file, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxProcCommandLineBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxProcCommandLineBytes || content[len(content)-1] != 0 {
		return false
	}
	arguments := bytes.Split(content[:len(content)-1], []byte{0})
	if len(arguments) != 2 || !bytes.Equal(arguments[1], []byte("-l")) {
		return false
	}
	switch string(arguments[0]) {
	case "bash", "/bin/bash", "/usr/bin/bash":
		return true
	default:
		return false
	}
}

func readProcStatus(path string, pid int) (procInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return procInfo{}, err
	}
	defer file.Close()
	info := procInfo{pid: pid}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64<<10)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			info.name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "State:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "State:"))
			if value != "" {
				info.state = value[0]
			}
		case strings.HasPrefix(line, "PPid:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			info.ppid, _ = strconv.Atoi(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return procInfo{}, err
	}
	if info.name == "" || info.state == 0 {
		return procInfo{}, fmt.Errorf("invalid process status for %d", pid)
	}
	return info, nil
}

func listeningSocketInodes(procRoot string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	for _, name := range []string{"tcp", "tcp6"} {
		file, err := os.Open(filepath.Join(procRoot, "net", name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024), 64<<10)
		first := true
		for scanner.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 10 && fields[3] == "0A" {
				result[fields[9]] = struct{}{}
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return result, nil
}

func socketInode(link string) string {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
}
