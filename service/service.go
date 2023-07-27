package service

import (
	"context"

	"github.com/qwertyqq2/microservTask/proto"
)

type Service interface {
	CheckVuln(ctx context.Context) error
}

// обернуть над Service nmap
type GRPCService struct {
	serv Service
	proto.UnimplementedNetVulnServiceServer
}

func (serv *GRPCService) CheckVuln(ctx context.Context, req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	return nil, nil
}

func (serv *GRPCService) Echo(ctx context.Context, req *proto.EchoReq) (*proto.EchoResp, error) {
	text := req.Req.Text
	println("receive %s", text)
	return &proto.EchoResp{
		Resp: &proto.Echo{
			Text: "ok",
		},
	}, nil
}
