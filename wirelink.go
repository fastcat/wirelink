// The wirelink command is the main entrypoint.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/fastcat/wirelink/cmd"
	"github.com/fastcat/wirelink/internal/networking/host"
)

func main() {
	cmd := cmd.New(os.Args)
	err := cmd.Init(host.MustCreateHost())
	// don't print on error just because help was requested
	if err != nil {
		if !errors.Is(err, pflag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "Fatal init error: %v\n", err)
			defer os.Exit(1)
		}
		return
	}
	if cmd.Server == nil {
		// --dump or such
		return
	}
	err = cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal run error: %v\n", err)
		defer os.Exit(1)
		return
	}
}
