// Package darwin provides an implementation of networking.Environment for the
// host darwin (macOS) system, leveraging the Go native package, and then
// filling in the gaps by exececuting command line tools such as ifconfig.
package darwin

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/native"
	"github.com/fastcat/wirelink/log"
)

// CreateDarwin makes an environment for the host using ifconfig
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
		ret[i] = e.interfaceFromGo(ifaces[i].(*native.GoInterface))
	}
	return ret, nil
}

func (e *darwinEnvironment) InterfaceByName(name string) (networking.Interface, error) {
	iface, err := e.GoEnvironment.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return e.interfaceFromGo(iface.(*native.GoInterface)), nil
}

func (e *darwinEnvironment) interfaceFromGo(iface *native.GoInterface) *darwinInterface {
	return &darwinInterface{*iface, e}
}

func (e *darwinEnvironment) Close() error {
	return e.GoEnvironment.Close()
}

type darwinInterface struct {
	native.GoInterface
	env *darwinEnvironment
}

var _ networking.Interface = (*darwinInterface)(nil)

func (i *darwinInterface) AddAddr(addr net.IPNet) error {
	family := "inet6"
	if addr.IP.To4() != nil {
		family = "inet"
	}
	// probably have to run as root because of this
	cmd := exec.Command("ifconfig", i.Name(), family, addr.String(), "alias")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to add %v to %s: %s: %w", addr, i.Name(), string(output), err)
	}
	log.Debug("ifconfig results: %s", string(output))
	return nil
}
