// Package pwnedgrpc provides a password checking client and server
// accessible via gRPC.
package pwnedgrpc

//go:generate protoc ./pwned.proto --go_out=plugins=grpc:internal/proto
