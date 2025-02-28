package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/target"
)

type IfDirty struct {
	outputs []string
	inputs  []string
	cmd     func(context.Context) error
}

func ifDirty(outputs ...string) *IfDirty {
	return &IfDirty{outputs: outputs}
}
func (id *IfDirty) from(inputs ...string) *IfDirty {
	id.inputs = append(id.inputs, inputs...)
	return id
}
func (id *IfDirty) then(cmd func(context.Context) error) *IfDirty {
	id.cmd = cmd
	return id
}

func (id *IfDirty) run(ctx context.Context) error {
	anyDirty := false
	for _, dst := range id.outputs {
		if dirty, err := target.Dir(dst, id.inputs...); err != nil {
			return err
		} else if dirty {
			anyDirty = true
			break
		}
	}
	if !anyDirty {
		if mg.Verbose() {
			fmt.Printf("clean: %s\n", strings.Join(id.outputs, ", "))
		}
		return nil
	}
	return id.cmd(ctx)
}
