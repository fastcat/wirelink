package main

import (
	"context"

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
	panic(`TODO:
rm -vf ./wirelink ./wirelink-cross-* $(GENERATED_SOURCES) $(patsubst %,%.tmp,$(GENERATED_SOURCES)) $(GOGENERATED_SOURCES) ./coverage.out ./coverage.html
`)
}

var Aliases = map[string]any{
	"lint": LintAll,
	"test": TestDefault,
}
