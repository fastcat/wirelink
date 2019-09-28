package main

import (
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/fastcat/wirelink/peerfacts"
	"github.com/fastcat/wirelink/server"
)

func main() {
	wgc, _ := wgctrl.New()
	dev, _ := wgc.Device("wg0")
	facts, _ := peerfacts.DeviceFacts(dev, 30*time.Second)
	for _, fact := range facts {
		fmt.Println(fact)
	}
	for _, peer := range dev.Peers {
		facts, _ := peerfacts.LocalFacts(&peer, 30*time.Second)
		for _, fact := range facts {
			fmt.Println(fact)
		}
	}

	server, err := server.Create(dev, 0)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	fmt.Printf("Server running on %v\n", server.Address())
	defer fmt.Println("Goodbye")
}
