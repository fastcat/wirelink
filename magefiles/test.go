package main

import (
	"context"
	"io/fs"
	"os"
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
func (Test) CoverCI(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "tool", "gotestsum",
		"--format=github-actions",
		"--junitfile=junit.xml",
		"--junitfile-project-name=wirelink",
		"--",
		"-vet=off", "-timeout=1m", "-covermode=atomic", "-coverpkg=./...", "-coverprofile=coverage.out", "./...",
	)
}
func (Test) CoverHTML(ctx context.Context) error {
	if err := ifDirty("coverage.html").from("coverage.out").then(func(ctx context.Context) error {
		return sh.RunV("go", "tool", "cover", "-html=coverage.out", "-o=coverage.html")
	}).run(ctx); err != nil {
		return err
	}
	return nil
}

func (Test) Fuzz(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)

	fuzzerDirs := map[string]bool{}
	if err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if d.IsDir() {
			if filepath.Base(path) == ".git" {
				return filepath.SkipDir
			}
			// recurse
			return nil
		} else if fuzzerDirs[filepath.Dir(path)] {
			// already found a fuzzer in this directory, skip it
			return filepath.SkipDir
		} else if !strings.HasSuffix(path, "_test.go") {
			// not a test file
			return nil
		}
		// TODO: stream the file, not just the lines
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for l := range strings.Lines(string(contents)) {
			if strings.HasPrefix(l, "func Fuzz") {
				fuzzerDirs[filepath.Dir(path)] = true
				// done with this dir
				return filepath.SkipDir
			}
		}
		return nil
	}); err != nil {
		return err
	}

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
