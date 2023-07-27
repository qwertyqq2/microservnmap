package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/qwertyqq2/microservTask/client"
	"github.com/qwertyqq2/microservTask/proto"
	"github.com/qwertyqq2/microservTask/service"
	"google.golang.org/grpc"
)

var (
	isClient   bool
	listenAddr = ":8000"
)

func ParseFlags() {
	pVerbose := flag.Bool("c", false, "Explain what's happening while program runs")
	flag.Parse()
	isClient = *pVerbose
}

func main() {
	ParseFlags()
	fmt.Println(isClient)
	closed := make(chan struct{})
	if !isClient {
		serv := service.GRPCService{}
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			log.Fatal(err)
		}
		server := grpc.NewServer()
		proto.RegisterNetVulnServiceServer(server, &serv)
		go func() {
			err := server.Serve(ln)
			if err != nil {
				log.Println(err)
			}
			closed <- struct{}{}
		}()
	} else {
		go func() {
			defer func() {
				closed <- struct{}{}
			}()
			cli, err := client.NewGRPCClient(listenAddr)
			if err != nil {
				log.Println(err)
				return
			}
			stdReader := bufio.NewReader(os.Stdin)

			for {
				fmt.Print("> ")
				sendData, err := stdReader.ReadString('\n')
				if err != nil {
					log.Println("Error reading from stdin")
					break
				}
				resp, err := cli.Echo(context.Background(), &proto.EchoReq{
					Req: &proto.Echo{
						Text: sendData,
					},
				})
				if err != nil {
					log.Println(err)
					return
				}
				fmt.Println("resp: ", resp.Resp.Text)
			}
		}()
	}

	<-closed
	println("some error")
}
