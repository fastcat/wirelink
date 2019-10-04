package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
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

	sigs := make(chan os.Signal, 5)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	timedout := time.After(45 * time.Second)

DONE:
	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGUSR1 {
				fmt.Println("Current facts")
				server.PrintFacts()
			} else {
				fmt.Printf("Received signal %v, stopping\n", sig)
				break DONE
			}
		case <-timedout:
			fmt.Println("Bored, quitting")
			break DONE
		}
	}

	fmt.Println("Stopping server")
	server.Stop()

	fmt.Println("Final facts")
	server.PrintFacts()
}
