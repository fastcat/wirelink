package main

import (
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/peerfacts"
	"github.com/fastcat/wirelink/server"
)

func main() {
	wgc, err := wgctrl.New()
	if err != nil {
		panic(err)
	}
	dev, err := wgc.Device("wg0")
	if err != nil {
		panic(err)
	}
	facts, err := peerfacts.DeviceFacts(dev, 30*time.Second)
	if err != nil {
		panic(err)
	}
	for _, fact := range facts {
		printFact(fact)
	}
	for _, peer := range dev.Peers {
		facts, _ := peerfacts.LocalFacts(&peer, 30*time.Second)
		for _, fact := range facts {
			printFact(fact)
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

func printFact(fact fact.Fact) {
	fmt.Println(fact)
	wf, err := fact.ToWire()
	if err != nil {
		panic(err)
	}
	wfd, err := wf.Serialize()
	if err != nil {
		panic(err)
	}
	fmt.Printf("  => (%d) %v\n", len(wfd), wfd)
}
