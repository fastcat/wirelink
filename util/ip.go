package util

import "net"

func NormalizeIP(ip net.IP) net.IP {
	n := ip.To4()
	if n == nil {
		n = ip.To16()
	}
	return n
}
