package config

// Server describes the configuration for the server, after parsing from various sources
type Server struct {
	Iface    string
	Port     int
	IsRouter bool
	Peers    Peers
}
