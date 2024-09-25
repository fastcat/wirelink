//go:build linux
// +build linux

// Package linux provides an implementation of networking.Environment for the
// host Linux system, leveraging the Go native package, and then filling in the
// gaps using netlink APIs.
package linux

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/native"
)

// CreateLinux makes an environment for the host using netlink
func CreateLinux() (networking.Environment, error) {
	nlh, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("unable to make a new netlink handle: %w", err)
	}

	ret := &linuxEnvironment{
		nlh: nlh,
	}

	return ret, nil
}

type linuxEnvironment struct {
	native.GoEnvironment
	nlh *netlink.Handle
}

// linuxEnvironment implements networking.Environment
var _ networking.Environment = (*linuxEnvironment)(nil)

// Interfaces implements Environment
func (e *linuxEnvironment) Interfaces() ([]networking.Interface, error) {
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

func (e *linuxEnvironment) InterfaceByName(name string) (networking.Interface, error) {
	iface, err := e.GoEnvironment.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return e.interfaceFromGo(iface.(*native.GoInterface))
}

func (e *linuxEnvironment) interfaceFromGo(iface *native.GoInterface) (*linuxInterface, error) {
	link, err := e.nlh.LinkByName(iface.Name())
	if err != nil {
		return nil, fmt.Errorf("unable to get netlink info for interface %s: %w", iface.Name(), err)
	}
	return &linuxInterface{*iface, link, e}, nil
}

func (e *linuxEnvironment) Close() error {
	if e.nlh != nil {
		e.nlh.Close()
		e.nlh = nil
	}
	return e.GoEnvironment.Close()
}

type linuxInterface struct {
	native.GoInterface
	link netlink.Link
	env  *linuxEnvironment
}

var _ networking.Interface = (*linuxInterface)(nil)

func (i *linuxInterface) AddAddr(addr net.IPNet) error {
	err := i.env.nlh.AddrAdd(i.link, &netlink.Addr{
		IPNet: &addr,
	})
	if err != nil {
		return fmt.Errorf("unable to add %v to %s: %w", addr, i.Name(), err)
	}
	return nil
}
