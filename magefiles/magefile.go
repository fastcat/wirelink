package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go/build"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var Default = Everything

func Compile(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "build", "-v", "./...")
}

func Wirelink(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "build", "-v", ".")
}
func WirelinkCross(ctx context.Context, arch string) error {
	mg.CtxDeps(ctx, Generate)
	// build these stripped
	return sh.RunWithV(
		map[string]string{
			"CGO_ENABLED": "0",
			"GOARCH":      "arch",
		},
		"go", "build", "-ldflags", "-s -w", "-o", "wirelink-cross-"+arch, "-v", ".",
	)
}

func Run(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "run", "-exec", "sudo", ".")
}

func DlvRunReal(ctx context.Context) error {
	mg.CtxDeps(ctx, Compile, Wirelink)
	return sh.RunV(
		"sudo", "$(GOPATH)/bin/dlv", "debug",
		"--only-same-user=false",
		"--headless",
		"--listen=:2345",
		"--log",
		"--api-version=2",
		"--",
		"--debug",
		"--iface=wg0",
	)
}

func Everything(ctx context.Context) {
	mg.CtxDeps(ctx,
		LintAll,
		Compile,
		Wirelink,
		TestDefault,
	)
}

func Clean(ctx context.Context) error {
	mg.CtxDeps(ctx, Checkinstall{}.Clean)
	for _, pattern := range []string{
		"./wirelink",
		"./wirelink-cross-*",
		"./coverage.out",
		"./coverage.html",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}
		for _, match := range matches {
			if err := os.RemoveAll(match); err != nil {
				return err
			}
		}
	}
	for _, l := range [][]string{generatedSources, goGeneratedSources} {
		for _, fn := range l {
			if err := os.RemoveAll(fn); err != nil {
				return err
			}
			if err := os.RemoveAll(fn + ".tmp"); err != nil {
				return err
			}
		}
	}
	return nil
}

var Aliases = map[string]any{
	"lint": LintAll,
	"test": TestDefault,
}

func init() {
	// make sure GOBIN is in PATH
	gobin := os.Getenv("GOBIN")
	if gobin == "" {
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		gobin = filepath.Join(gopath, "bin")
	}
	pathEntries := filepath.SplitList(os.Getenv("PATH"))
	if !slices.Contains(pathEntries, gobin) {
		pathEntries = append([]string{gobin}, pathEntries...)
		os.Setenv("PATH", strings.Join(pathEntries, string(filepath.ListSeparator)))
	}
}
