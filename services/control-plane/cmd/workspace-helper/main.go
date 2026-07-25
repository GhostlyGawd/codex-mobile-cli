package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

func main() {
	if filepath.Base(os.Args[0]) == "codex" {
		if err := workspacehelper.RunCodex(os.Args[1:], workspacehelper.DefaultRoot, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, "Codex launch failed")
			os.Exit(1)
		}
		return
	}
	if handled, err := workspacehelper.RunTerminalIfRequested(os.Args[1:], workspacehelper.DefaultRoot); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "terminal launch failed")
			os.Exit(1)
		}
		return
	}
	helper, err := workspacehelper.New(workspacehelper.DefaultRoot)
	if err == nil {
		serveContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = helper.Serve(serveContext, os.Stdin, os.Stdout)
		cancel()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "workspace helper failed")
		os.Exit(1)
	}
}
