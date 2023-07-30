package main

import (
	"net"

	"github.com/qwertyqq2/microservTask/proto"
	"github.com/qwertyqq2/microservTask/service"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	listenAddr = ":8000"
)

func main() {
	closed := make(chan struct{})
	serv := service.NewGRPCService()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	proto.RegisterNetVulnServiceServer(server, serv)
	go func() {
		err := server.Serve(ln)
		if err != nil {
			log.Println(err)
		}
		closed <- struct{}{}
	}()

	<-closed
	println("some error")
}
