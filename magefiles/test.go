package main

import (
	"context"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func TestDefault(ctx context.Context) error {
	mg.CtxDeps(ctx, LintAll, Test{}.GoRace)
	return nil
}

type Test mg.Namespace

func (Test) Go(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "test", "-vet=off", "-timeout=20s", "./...")
}
func (Test) GoRace(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "test", "-vet=off", "-timeout=1m", "-race", "./...")
}

func (Test) Stress(ctx context.Context) error {
	mg.CtxDeps(ctx, Test{}.StressGo, Test{}.StressRace)
	return nil
}
func (Test) StressGo(ctx context.Context) error {
	return sh.RunV("go", "test", "-vet=off", "-short", "-timeout=2m", "-count=1000", "./...")
}
func (Test) StressRace(ctx context.Context) error {
	return sh.RunV("go", "test", "-vet=off", "-short", "-timeout=5m", "-race", "-count=1000", "./...")
}

func (Test) Cover(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "test", "-vet=off", "-timeout=1m", "-covermode=atomic", "-coverpkg=./...", "-coverprofile=coverage.out", "./...")
}
func (Test) CoverHTML(ctx context.Context) error {
	if err := ifDirty("coverage.out").then(Test{}.Cover).run(ctx); err != nil {
		return err
	}
	if err := ifDirty("coverage.html").from("coverage.out").then(func(ctx context.Context) error {
		return sh.RunV("go", "tool", "cover", "-html=coverage.out", "-o=coverage.html")
	}).run(ctx); err != nil {
		return err
	}
	return nil
}

func (Test) Fuzz(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	panic(`TODO:
fgrep -rlZ 'func Fuzz' */ | xargs -0 dirname -z | sort -zu \
	| xargs -0 -t -I_PKG_ go test ./_PKG_ -fuzz=.* -fuzztime=1m
`)
}
