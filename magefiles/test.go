package main

import (
	"context"
	"path/filepath"
	"strings"

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
	// TODO: pipeline this better
	dirs, err := filepath.Glob("*/")
	if err != nil {
		return err
	}
	fgArgs := []string{"-rlZ", "func Fuzz"}
	fgArgs = append(fgArgs, dirs...)
	fuzzersOut, err := sh.Output("fgrep", fgArgs...)
	if err != nil {
		return err
	}
	fuzzerFiles := strings.Split(fuzzersOut, "\x00")
	fuzzerDirs := map[string]bool{}
	for _, fuzzerFile := range fuzzerFiles {
		if len(fuzzerFile) != 0 {
			fuzzerDirs[filepath.Dir(fuzzerFile)] = true
		}
	}
	delete(fuzzerDirs, "magefiles")
	deps := make([]any, 0, len(fuzzerDirs))
	for fuzzerDir := range fuzzerDirs {
		deps = append(deps, mg.F(Test{}.fuzzDir, fuzzerDir))
	}
	mg.CtxDeps(ctx, deps...)
	return nil
}

func (Test) fuzzDir(ctx context.Context, dir string) error {
	return sh.RunV("go", "test", "./"+dir, "-fuzz=.*", "-fuzztime=1m")
}
