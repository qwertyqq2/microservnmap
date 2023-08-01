package main

import (
	"net"

	"github.com/qwertyqq2/microservTask/configs"
	"github.com/qwertyqq2/microservTask/proto"
	"github.com/qwertyqq2/microservTask/service"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	conf, err := configs.Parse()
	if err != nil {
		panic(err)
	}

	logger := logrus.New()
	level, err := logrus.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	logger.SetLevel(level)

	closed := make(chan struct{})
	serv := service.NewGRPCService(logger)
	ln, err := net.Listen("tcp", conf.Address)
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	proto.RegisterNetVulnServiceServer(server, serv)
	go func() {
		logger.Info("Start serve...")
		err := server.Serve(ln)
		if err != nil {
			log.Println(err)
		}
		closed <- struct{}{}
	}()

	<-closed
	println("some error")
}
