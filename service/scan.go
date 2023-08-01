package service

import (
	"context"

	"github.com/Ullaakut/nmap/v3"
	"github.com/sirupsen/logrus"
)

func scan(ctx context.Context, logger *logrus.Logger, targs []string, ports []string) (*nmap.Run, error) {
	scanner, err := createVulnScanner(ctx, targs, ports)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	res, warn, err := scanner.Run()
	if err != nil {
		logger.Error("err scan")
		for _, w := range *warn {
			logger.Warn(w)
		}
		return nil, err
	}

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
