// A dependency-free health probe for the scratch control-plane image.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: http-healthcheck <url>")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(os.Args[1]) // #nosec G107 -- URL is a fixed image health-check argument.
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "unexpected health status: %s\n", response.Status)
		os.Exit(1)
	}
}
