package main

import (
	"context"

	"github.com/magefile/mage/sh"
)

var toolsDev = []string{
	"github.com/go-delve/delve/cmd/dlv@latest",
	"github.com/golangci/golangci-lint/cmd/golangci-lint@latest",
}

func InstallToolsDev(ctx context.Context) error {
	for _, t := range toolsDev {
		if err := sh.RunV("go", "install", t); err != nil {
			return err
		}
	}
	return nil
}
