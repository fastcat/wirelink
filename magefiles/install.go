package main

import (
	"context"
	"os"

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
	panic(`TODO:
rm -vf ./packaging/*checkinstall/*.deb
rm -rvf ./packaging/*checkinstall/doc-pak/
`)
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
	panic(`TODO:
# extra quoting on some args to work around checkinstall bugs:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=785441
	cd ./packaging/checkinstall && fakeroot checkinstall \
		--type=debian \
		--install=no \
		--fstrans=yes \
		--pkgarch=$* \
		--pkgname=wirelink \
		--pkgversion=$(PKGVER) \
		--pkgrelease=$(PKGREL) \
		--pkglicense=AGPL-3 \
		--pkggroup=net \
		--pkgsource=https://github.com/fastcat/wirelink \
		--maintainer="'Matthew Gabeler-Lee <cheetah@fastcat.org>'" \
		--requires=wireguard-tools \
		--recommends="'wireguard-dkms | wireguard-modules'" \
		--reset-uids=yes \
		--backup=no \
		$(MAKE) -C ../../ sysinstall-cross-$* \
		</dev/null
`)
}
