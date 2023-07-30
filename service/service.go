package service

import (
	"context"

	"github.com/Ullaakut/nmap/v3"
	"github.com/qwertyqq2/microservTask/proto"
	"github.com/qwertyqq2/microservTask/service/xmlparse"
	log "github.com/sirupsen/logrus"
)

// обернуть над Service nmap
type GRPCService struct {
	serv Service
	proto.UnimplementedNetVulnServiceServer
}

func NewGRPCService() *GRPCService {
	return &GRPCService{serv: &serviceNmap{}}
}

func (s *GRPCService) CheckVuln(ctx context.Context, req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	log.Info("New call")
	res, err := s.serv.Scan(
		ctx,
		&request{
			targs: req.GetTargets(),
			ports: req.GetTcpPorts(),
		},
	)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return s.toProto(res), nil
}

func (s *GRPCService) toProto(res *nmap.Run) *proto.CheckVulnResponse {
	log.Info("Marsh to proto")
	resp := &proto.CheckVulnResponse{}
	resp.Results = make([]*proto.TargetResult, 0)

	for _, host := range res.Hosts {
		for _, port := range host.Ports {
			vulns := xmlparse.FindVulnsFromPort(port)
			if len(vulns) == 0 {
				continue
			}
			targ := &proto.TargetResult{
				Target: host.IPIDSequence.Values,
				Service: &proto.Service{
					Name:    port.Service.Name,
					Version: port.Service.Version,
					TcpPort: int32(port.ID),
					Vulns:   vulns,
				},
			}
			resp.Results = append(resp.Results, targ)

		}

	}
	return resp
}

func (s *GRPCService) Echo(ctx context.Context, req *proto.EchoReq) (*proto.EchoResp, error) {
	text := req.Req.Text
	println("receive %s", text)
	return &proto.EchoResp{
		Resp: &proto.Echo{
			Text: "ok",
		},
	}, nil
}
