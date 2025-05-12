package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func Install(ctx context.Context) error {
	mg.CtxDeps(ctx, Generate)
	return sh.RunV("go", "install", "-v")
}

func SysInstall(ctx context.Context) error {
	mg.CtxDeps(ctx, Wirelink)
	return sysinstall(ctx, "wirelink")
}

func SysInstallCross(ctx context.Context, arch string) error {
	mg.CtxDeps(ctx, mg.F(WirelinkCross, arch))
	return sysinstall(ctx, "wirelink-cross-"+arch)
}

func sysinstall(ctx context.Context, src string) error {
	if err := sh.RunV("install", src, PREFIX+"/bin/wirelink"); err != nil {
		return err
	}
	if err := sh.RunV("install", "-m", "644", "packaging/wirelink@.service", "/lib/systemd/system/"); err != nil {
		return err
	}
	if err := sh.RunV("install", "-m", "644", "packaging/wl-quick@.service", "/lib/systemd/system/"); err != nil {
		return err
	}
	return nil
}

type Checkinstall mg.Namespace

func (Checkinstall) Clean(ctx context.Context) error {
	for _, pattern := range []string{
		"./packaging/*checkinstall/*.deb",
		"./packaging/*checkinstall/doc-pak",
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
	return nil
}

func (Checkinstall) Prep(ctx context.Context, arch string) error {
	mg.CtxDeps(ctx, mg.F(WirelinkCross, arch))
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}
	if err := os.MkdirAll("packaging/wirelink-checkinstall/doc-pak", 0777); err != nil {
		return err
	}
	args := []string{"-m", "644"}
	args = append(args, DOCSFILES...)
	args = append(args, "./packaging/wirelink-checkinstall/doc-pak/")
	if err := sh.RunV("install", args...); err != nil {
		return err
	}
	return nil
}

func (Checkinstall) Cross(ctx context.Context, arch string) error {
	mg.CtxDeps(ctx, mg.F(Checkinstall{}.Prep, arch))
	// mage's sh package doesn't provide a way to override cwd, so we do this raw.
	// Some args have extra quoting to work around checkinstall bugs, see:
	// https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=785441
	vi, err := getVersions(ctx)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "fakeroot",
		"checkinstall",
		"--type=debian",
		"--install=no",
		"--fstrans=yes",
		"--pkgarch="+arch,
		"--pkgname=wirelink",
		"--pkgversion="+vi.pkgVer,
		"--pkgrelease="+vi.pkgRel,
		"--pkglicense=AGPL-3",
		"--pkggroup=net",
		"--pkgsource=https://github.com/fastcat/wirelink",
		"--maintainer='Matthew Gabeler-Lee <cheetah@fastcat.org>'",
		"--requires=wireguard-tools",
		"--recommends='wireguard-dkms | wireguard-modules'",
		"--reset-uids=yes",
		"--backup=no",
		// the real command, need to get back to the original directory
		"/bin/sh", "-c",
		fmt.Sprintf("cd ../../ && %s %s %s", os.Args[0], "sysInstallCross", arch),
	)
	cmd.Dir = "./packaging/checkinstall"
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
