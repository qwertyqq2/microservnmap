package service

import (
	"context"

	"github.com/Ullaakut/nmap/v3"
	"github.com/qwertyqq2/microservTask/proto"
	parser "github.com/qwertyqq2/microservTask/service/parser"
	"github.com/qwertyqq2/microservTask/utils"
	"github.com/sirupsen/logrus"
)

/*
Пакет service представляет собой обертку
над утилитой nmap. В качестве основы была взята
реализация nmap на языке go: github.com/Ullaakut/nmap
*/

const (
	defualtMaxPort = 1000
)

// grpc сервис обертка над nmap
type GRPCService struct {
	logger *logrus.Logger
	proto.UnimplementedNetVulnServiceServer
}

func NewGRPCService(logger *logrus.Logger) *GRPCService {
	return &GRPCService{logger: logger}
}

// CheckVuln сканирует порты и цели указанные в req
// Если цели не заданы, то возвращается ошибка
// Если порты не заданы, то будут сканироваться все порты
// в диапозоне 1-1000
// Учтите, что сканирование всех портов на удаленном хосте
// может занять некоторое время
func (s *GRPCService) CheckVuln(ctx context.Context, req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	s.logger.Info("New request receive")
	if len(req.Targets) == 0 {
		s.logger.Error(ErrUndefinedTargers)
		return nil, ErrUndefinedTargers
	}
	var ports []string
	if len(req.TcpPorts) == 0 {
		ports = make([]string, 0, defualtMaxPort)
		var port int32
		for port = 1; port < defualtMaxPort; port++ {
			ports = append(ports, utils.IntToString(port))
		}
	} else {
		ports = make([]string, 0, len(req.TcpPorts))
		for _, port := range req.TcpPorts {
			ports = append(ports, utils.IntToString(port))
		}
	}

	// начало сканирования
	res, err := scan(ctx, s.logger, req.Targets, ports)
	if err != nil {
		return nil, err
	}
	s.logger.Info("Send response")
	return s.toProto(res), nil
}

// toProto преобразует результат сканирования в прото файл
func (s *GRPCService) toProto(res *nmap.Run) *proto.CheckVulnResponse {
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
