package main

import (
	"context"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func LintAll(ctx context.Context) error {
	mg.CtxDeps(ctx, Lint{}.GolangCI, Lint{}.Vulncheck)
	return nil
}

type Lint mg.Namespace

func (Lint) GolangCI(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("golangci-lint", "run")
}
func (Lint) Fix(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("golangci-lint", "run", "--fix")
}
func (Lint) Vulncheck(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "tool", "govulncheck", "-test", "./...")
}
