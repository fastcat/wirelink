package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func PreDebug(ctx context.Context) error {
	// compile it once to get the intermediate file
	if err := sh.RunV("go", "tool", "mage", "-f", "-keep", "-compile", "build"); err != nil {
		return err
	}
	srcs, err := filepath.Glob("magefiles/*.go")
	if err != nil {
		return err
	}
	for i := range srcs {
		srcs[i] = filepath.Base(srcs[i])
	}
	// compile it again for debugging
	c := exec.CommandContext(ctx, "go", "build", "-o", "build", "-gcflags=-N -l")
	c.Args = append(c.Args, srcs...)
	c.Stdin, c.Stdout, c.Stderr = nil, os.Stdout, os.Stderr
	c.Dir = "./magefiles"
	if mg.Verbose() {
		quoted := make([]string, 0, len(c.Args)-1)
		for _, a := range c.Args[1:] {
			quoted = append(quoted, strconv.Quote(a))
		}
		fmt.Printf("exec: %s %s\n", filepath.Base(c.Path), strings.Join(quoted, " "))
	}
	if err := c.Run(); err != nil {
		return err
	}
	return nil
}
