package config

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

// Server describes the configuration for the server, after parsing from various sources
type Server struct {
	Iface    string
	Port     int
	IsRouter bool
	Peers    map[wgtypes.Key]*Peer
}
