package service

import (
	"context"
	"fmt"

	"github.com/Ullaakut/nmap/v3"
	"github.com/qwertyqq2/microservTask/utils"
	log "github.com/sirupsen/logrus"
)

type Service interface {
	Scan(ctx context.Context, req *request) (*nmap.Run, error)
}

type request struct {
	targs []string
	ports []int32
}

type serviceNmap struct {
}

func vulnScanner(ctx context.Context, req *request) (*nmap.Scanner, error) {
	ports := utils.IntsToStrings(req.ports)
	return nmap.NewScanner(
		ctx,
		//nmap.WithPorts(strconv.FormatInt(int64(req.port), 10)),
		nmap.WithPorts(ports...),
		nmap.WithACKDiscovery(ports...),
		nmap.WithTargets(req.targs...),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			return p.Protocol == "tcp"
		}),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
	)
}

func (s *serviceNmap) Scan(ctx context.Context, req *request) (*nmap.Run, error) {
	log.Info("Start scan...")

	scanner, err := vulnScanner(ctx, req)
	if err != nil {
		return nil, err
	}

	fmt.Println(scanner.Args())

	res, warn, err := scanner.Run()
	if err != nil {
		return nil, err
	}

	log.Info("Receive from nmap")

	if err != nil {
		for _, w := range *warn {
			log.Warn(w)
		}
		return nil, err
	}

	return res, nil

}
