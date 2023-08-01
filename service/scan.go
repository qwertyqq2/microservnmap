package service

import (
	"context"

	"github.com/Ullaakut/nmap/v3"
	log "github.com/sirupsen/logrus"
)

func scan(ctx context.Context, targs []string, ports []string) (*nmap.Run, error) {
	log.Info("Start scan...")

	scanner, err := createVulnScanner(ctx, targs, ports)
	if err != nil {
		return nil, err
	}

	res, warn, err := scanner.Run()
	if err != nil {
		for _, w := range *warn {
			log.Warn(w)
		}
		return nil, err
	}

	log.Info("Receive from nmap")

	return res, nil

}

func createVulnScanner(ctx context.Context, targs []string, ports []string) (*nmap.Scanner, error) {
	return nmap.NewScanner(
		ctx,
		nmap.WithPorts(ports...),
		nmap.WithACKDiscovery(ports...),
		nmap.WithTargets(targs...),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			return p.Protocol == "tcp"
		}),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
	)
}
