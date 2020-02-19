package vnet

import (
	"errors"
	"net"

	"github.com/fastcat/wirelink/internal/networking"
)

// hostEnvironment wraps a Host to make it function as a virtual UDP networking
// Environment.
type hostEnvironment struct {
	h *Host
}

var _ networking.Environment = &hostEnvironment{}

// Wrap provides an Environment view of a Host
func (h *Host) Wrap() networking.Environment {
	return &hostEnvironment{h}
}

// Close implements Environment
func (he *hostEnvironment) Close() error {
	h := he.h
	if h == nil {
		return errors.New("Already closed")
	}
	h.Close()
	return nil
}

// Interfaces implements Environment
func (he *hostEnvironment) Interfaces() ([]networking.Interface, error) {
	he.h.m.Lock()
	defer he.h.m.Unlock()
	ret := make([]networking.Interface, 0, len(he.h.interfaces))
	for _, i := range he.h.interfaces {
		ret = append(ret, i.Wrap())
	}
	return ret, nil
}

// InterfaceByName implements Environment
func (he *hostEnvironment) InterfaceByName(name string) (networking.Interface, error) {
	he.h.m.Lock()
	defer he.h.m.Unlock()
	i := he.h.interfaces[name]
	if i != nil {
		return i.Wrap(), nil
	}
	return nil, &net.OpError{Op: "route", Net: "ip+net", Err: errors.New("no such network interface")}
}

// ListenUDP implements Environment
func (he *hostEnvironment) ListenUDP(network string, laddr *net.UDPAddr) (networking.UDPConn, error) {
	// TODO: validate network & local address

	// if laddr specifies a zone, try to add the socket to a specific interface
	if laddr.Zone != "" {
		he.h.m.Lock()
		defer he.h.m.Unlock()
		i := he.h.interfaces[laddr.Zone]
		if i == nil {
			// TODO: this error probably isn't quite right
			return nil, &net.OpError{Op: "listen", Net: network, Addr: laddr, Err: errors.New("no such network interface")}
		}
		s := i.AddSocket(laddr)
		return s.Connect(), nil
	}

	// this one will take its own lock, so we don't take our own on this branch
	s := he.h.AddSocket(laddr)
	return s.Connect(), nil
}
