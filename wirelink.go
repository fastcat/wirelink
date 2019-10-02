package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/fastcat/wirelink/server"
)

func main() {
	wgc, err := wgctrl.New()
	if err != nil {
		panic(err)
	}

	server, err := server.Create(wgc, "wg0", 0)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	fmt.Printf("Server running on %v\n", server.Address())
	defer fmt.Println("Goodbye")

	server.PrintFacts()
}
