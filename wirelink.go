package main

import (
	"fmt"
	"time"

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

	fmt.Printf("Server running on [%v]:%v\n", server.Address(), server.Port())
	defer fmt.Println("Goodbye")

	count, errs := server.BroadcastFacts(5 * time.Second)
	if errs != nil {
		fmt.Println(errs)
	}
	fmt.Printf("Sent %d fact packets\n", count)

	time.Sleep(45 * time.Second)
}
