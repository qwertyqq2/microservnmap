package service

import (
	"context"

	"github.com/Ullaakut/nmap/v3"
	"github.com/qwertyqq2/microservTask/proto"
	parser "github.com/qwertyqq2/microservTask/service/parser"
	"github.com/qwertyqq2/microservTask/utils"
	log "github.com/sirupsen/logrus"
)

// обернуть над Service nmap
type GRPCService struct {
	proto.UnimplementedNetVulnServiceServer
}

func NewGRPCService() *GRPCService {
	return &GRPCService{}
}

func (s *GRPCService) CheckVuln(ctx context.Context, req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	log.Info("New call")
	var ports []string
	if len(req.TcpPorts) == 0 {
		var port int32
		for port = 0; port < 1000; port++ {
			ports = append(ports, utils.IntToString(port))
		}
	} else {
		for _, port := range req.TcpPorts {
			ports = append(ports, utils.IntToString(port))
		}
	}
	res, err := scan(ctx, req.Targets, ports)
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
			vulns := parser.FindVulnsFromPort(port)
			if len(vulns) == 0 {
				continue
			}
			targ := &proto.TargetResult{
				Target: host.Addresses[0].Addr,
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
