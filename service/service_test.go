package service

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/qwertyqq2/microservTask/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func defualtPorts() []int32 {
	return []int32{7000, 7500, 7600}
}

func defualtAddressServer() string {
	return ":8000"
}

func defualtAddressClient() string {
	return ":8800"
}

func defualtTargerts() []string {
	return []string{"localhost", "scanme.nmap.org"}
}

func startServer(t *testing.T, ctx context.Context) error {
	serv := NewGRPCService(logrus.New())
	ln, err := net.Listen("tcp", defualtAddressServer())
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	proto.RegisterNetVulnServiceServer(server, serv)
	go func() {
		err := server.Serve(ln)
		if err != nil {
			t.Fatal(err)
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			server.Stop()
		}
	}()
	return nil
}

func clientConnect(t *testing.T) proto.NetVulnServiceClient {
	cliConn, err := grpc.Dial(defualtAddressServer(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return proto.NewNetVulnServiceClient(cliConn)
}

func TestEmptyFields(t *testing.T) {
	testValidationEmptyFieldsCases := []struct {
		name string
		req  *proto.CheckVulnRequest
	}{
		{name: "empty req", req: &proto.CheckVulnRequest{}},
		{name: "empty targers", req: &proto.CheckVulnRequest{TcpPorts: defualtPorts()}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	startServer(t, ctx)

	cli := clientConnect(t)

	for _, tc := range testValidationEmptyFieldsCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cli.CheckVuln(ctx, tc.req)
			if err == nil {
				t.Fatal("its not true")
			}

		})
	}

	testProccessCases := []struct {
		name string
		req  *proto.CheckVulnRequest
	}{
		{name: "localhost all ports", req: &proto.CheckVulnRequest{Targets: []string{"localhost"}}},
		{name: "localhost certain ports", req: &proto.CheckVulnRequest{Targets: []string{"localhost"}, TcpPorts: []int32{7000, 7500}}},
		{name: "many hosts all ports", req: &proto.CheckVulnRequest{
			Targets: []string{"localhost", "scanme.nmap.org"},
		}},
		{name: "many hosts certain ports", req: &proto.CheckVulnRequest{
			Targets:  []string{"localhost", "scanme.nmap.org"},
			TcpPorts: []int32{7000, 7500},
		}},
	}

	for _, tc := range testProccessCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cli.CheckVuln(ctx, tc.req)
			if err != nil {
				t.Fatal(err)
			}

		})
	}

}
