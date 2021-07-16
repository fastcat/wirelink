package darwin

import (
	"net"
	"os/exec"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/native"
	"github.com/pkg/errors"
)

func CreateDarwin() (networking.Environment, error) {
	return &darwinEnvironment{}, nil
}

type darwinEnvironment struct {
	native.GoEnvironment
}

var _ networking.Environment = (*darwinEnvironment)(nil)

func (e *darwinEnvironment) Interfaces() ([]networking.Interface, error) {
	ifaces, err := e.GoEnvironment.Interfaces()
	if err != nil {
		return nil, err
	}
	ret := make([]networking.Interface, len(ifaces))
	for i := range ifaces {
		// TODO: may be faster to fetch all links and join them?
		ret[i], err = e.interfaceFromGo(ifaces[i].(*native.GoInterface))
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (e *darwinEnvironment) InterfaceByName(name string) (networking.Interface, error) {
	iface, err := e.GoEnvironment.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return e.interfaceFromGo(iface.(*native.GoInterface))
}

func (e *darwinEnvironment) interfaceFromGo(iface *native.GoInterface) (*darwinInterface, error) {
	return &darwinInterface{*iface, e}, nil
}

func (e *darwinEnvironment) Close() error {
	if err := e.GoEnvironment.Close(); err != nil {
		return err
	}
	return nil
}

type darwinInterface struct {
	native.GoInterface
	env *darwinEnvironment
}

var _ networking.Interface = (*darwinInterface)(nil)

func (i *darwinInterface) AddAddr(addr net.IPNet) error {
	// probably have to run as root because of this
	cmd := exec.Command("ifconfig", i.Name(), addr.String(), "alias")
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "Unable to add %v to %s", addr, i.Name())
	}
	return nil
}
