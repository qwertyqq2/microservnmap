package service

import (
	"context"

	"github.com/Ullaakut/nmap/v3"
	"github.com/sirupsen/logrus"
)

// scan сканирует цели и порты заданные в targs и ports соответветственно
// Параметры сканера задаются по умолчанию в функции createVulnScanner
func scan(ctx context.Context, logger *logrus.Logger, targs []string, ports []string) (*nmap.Run, error) {
	scanner, err := createVulnScanner(ctx, targs, ports)
	if err != nil {
		logger.Error(ErrCreateScanner)
		return nil, ErrCreateScanner
	}

	res, warn, err := scanner.Run()
	if err != nil {
		logger.Error(ErrRunScanner)
		for _, w := range *warn {
			logger.Warn(w)
		}
		return nil, ErrRunScanner
	}

	return res, nil

}

// createVulnScanner создает новый nmap сканер
// По умолчанию выбраны параметры TimingAggressive, фильтр
// на протокол портов tcp, скрипт vulners
func createVulnScanner(ctx context.Context, targs []string, ports []string) (*nmap.Scanner, error) {
	return nmap.NewScanner(
		ctx,
		nmap.WithPorts(ports...),
		nmap.WithTargets(targs...),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			return p.Protocol == "tcp"
		}),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
	)
}
