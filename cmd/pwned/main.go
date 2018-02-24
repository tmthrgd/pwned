package main

import (
	"flag"
	"log"
	"net"

	"github.com/tmthrgd/pwned"
	"github.com/tmthrgd/pwned/gateway"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", ":8080", "the address to listen on")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	gs := grpc.NewServer()
	pwned.NewServer(gateway.New()).Attach(gs)
	log.Fatal(gs.Serve(ln))
}
