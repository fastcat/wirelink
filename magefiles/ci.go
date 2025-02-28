package main

import (
	"context"
	"strconv"

	"github.com/magefile/mage/sh"
)

func Deepen(ctx context.Context) error {
	if err := sh.RunV("git", "fetch", "origin", "+refs/tags/*:refs/tags/*"); err != nil {
		return err
	}
	d := 30
	for {
		if _, err := getVersions(ctx); err == nil {
			break
		}
		if err := sh.RunV("git", "fetch", "--deepen="+strconv.Itoa(d), "origin", "+refs/tags/*:refs/tags/*"); err != nil {
			return err
		}
		d += 10
	}
	return nil
}
