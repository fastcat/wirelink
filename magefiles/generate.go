package main

import (
	"bytes"
	"context"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var generatedSources = []string{
	"internal/version.go",
}
var goGeneratedSources = []string{
	"internal/mocks/WgClient.go",
	"trust/mock_Evaluator_test.go",
	"internal/networking/mocks/Environment.go",
	"internal/networking/mocks/Interface.go",
	"internal/networking/mocks/UDPConn.go",
}
var generated = append(append([]string{}, generatedSources...), goGeneratedSources...)

func Generate(ctx context.Context) error {
	runs := make([]any, len(generators))
	for i := range generators {
		// can't pass it g.run because those will all look like the same target to
		// it and get deduplicated
		runs[i] = mg.F(runGen, i)
	}
	mg.CtxDeps(ctx, runs...)
	return nil
}

func runGen(ctx context.Context, i int) error {
	return generators[i].run(ctx)
}

var generators = []*IfDirty{
	ifDirty("internal/version.go").
		from("internal/version.go.in", ".git/HEAD", ".git/index").
		then(buildVersion),
	ifDirty(goGeneratedSources...).then(goGenerate),
}

func buildVersion(ctx context.Context) error {
	in, err := os.ReadFile("internal/version.go.in")
	if err != nil {
		return err
	}
	v, err := getVersions(ctx)
	if err != nil {
		return err
	}
	out := bytes.ReplaceAll(in, []byte("__GIT_VERSION__"), []byte(v.pkgVerRel))
	if err := safeOverwrite("internal/version.go", out, 0666); err != nil {
		return err
	}
	return nil
}

func goGenerate(ctx context.Context) error {
	return sh.RunV("go", "generate", "./...")
}

func safeOverwrite(dst string, content []byte, perm os.FileMode) error {
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, content, perm); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
