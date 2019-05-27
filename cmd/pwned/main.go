package main

import (
	"flag"
	"log"
	"net"

	"google.golang.org/grpc"
	"tmthrgd.dev/go/pwned/gateway"
	pwnedgrpc "tmthrgd.dev/go/pwned/grpc"
)

func main() {
	addr := flag.String("addr", ":8080", "the address to listen on")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	gs := grpc.NewServer()
	pwnedgrpc.NewServer(gateway.New()).Attach(gs)
	log.Fatal(gs.Serve(ln))
}
