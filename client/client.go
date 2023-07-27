package client

import (
	"github.com/qwertyqq2/microservTask/proto"
	"google.golang.org/grpc"
)

func NewGRPCClient(remoteAddr string) (proto.NetVulnServiceClient, error) {
	conn, err := grpc.Dial(remoteAddr, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	c := proto.NewNetVulnServiceClient(conn)

	return c, nil
}
