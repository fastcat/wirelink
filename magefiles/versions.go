package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/magefile/mage/sh"
)

type versions struct {
	pkgVerRel string
	pkgVer    string
	pkgRel    string
}

var getVersions = sync.OnceValues(func() (versions, error) {
	out, err := sh.Output("git", "describe", "--long", "--dirty=+")
	if err != nil {
		return versions{}, err
	}
	pkgVerRel := strings.TrimPrefix(out, "v")
	pkgVer, pkgRel, _ := strings.Cut(pkgVerRel, "-")
	return versions{pkgVerRel, pkgVer, pkgRel}, nil
})

func Info() error {
	v, err := getVersions()
	if err != nil {
		return err
	}
	fmt.Printf("PKGVERREL=%s\n", v.pkgVerRel)
	fmt.Printf("PKGVER=%s\n", v.pkgVer)
	fmt.Printf("PKGREL=%s\n", v.pkgRel)
	// fmt.Printf("GOPATH=%s\n", /*FIXME*/)
	fmt.Printf("PATH=%s\n", os.Getenv("PATH"))
	return nil
}
