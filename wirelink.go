package main

import (
	"fmt"
	"time"

	"github.com/fastcat/wirelink/peerfacts"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func main() {
	wgc, _ := wgctrl.New()
	dev, _ := wgc.Device("wg0")
	for _, peer := range dev.Peers {
		facts, _ := peerfacts.LocalFacts(&peer, 30*time.Second)
		for _, fact := range facts {
			fmt.Println(fact)
		}
	}
}
