package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v3"
	"github.com/qwertyqq2/microservTask/proto"
	"github.com/qwertyqq2/microservTask/utils"
)

func main() {
	scan, err := nmap.NewScanner(
		context.Background(),
		//nmap.WithPorts(strconv.FormatInt(int64(req.port), 10)),
		nmap.WithPorts("631", "8800"),
		nmap.WithTargets("localhost"),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			return p.Protocol == "tcp"
		}),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
	)

	if err != nil {
		log.Fatal(err)
	}
	res, _, err := scan.Run()
	if err != nil {
		log.Fatal(err)
	}

	for _, host := range res.Hosts {
		for _, port := range host.Ports {
			tcpPort := port.ID
			version := port.Service.Version
			name := port.Service.Name
			vulns := findVulns(port)
			if len(vulns) != 0 {
				fmt.Printf("port: %d, vers: %s, name: %s\n", tcpPort, version, name)
				for _, v := range vulns {
					fmt.Println(v.Identifier, v.CvssScore)
				}
				fmt.Println()
			}
		}
	}

}

func findVulns(port nmap.Port) []*proto.Vulnerability {
	var vulns []*proto.Vulnerability
	stack := []interface{}{port}

	for _, script := range port.Scripts {
		if script.ID == "vulners" {
			stack = append(stack, script)
		}
	}

	var (
		tempID   string
		tempCCVS string
	)

	for len(stack) > 0 {
		// Pop the top element from the stack
		obj := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		switch v := obj.(type) {
		case nmap.Script:
			stack = append(stack, toInterfaceSlice(v.Tables)...)
		case nmap.Table:
			for _, el := range v.Elements {
				if el.Key == "id" {
					tempID = el.Value
				}
				if el.Key == "cvss" {
					tempCCVS = el.Value
				}
			}
			if tempID != "" && tempCCVS != "" {
				vulns = append(vulns, &proto.Vulnerability{
					Identifier: tempID,
					CvssScore:  utils.StringToFloat(tempCCVS),
				})
			}
			tempID = ""
			tempCCVS = ""
			stack = append(stack, toInterfaceSlice(v.Tables)...)
		}
	}

	return vulns
}

func toInterfaceSlice(slice interface{}) []interface{} {
	s := make([]interface{}, 0)
	switch slice.(type) {
	case []nmap.Script:
		for _, v := range slice.([]nmap.Script) {
			s = append(s, v)
		}
	case []nmap.Table:
		for _, v := range slice.([]nmap.Table) {
			s = append(s, v)
		}
	case []nmap.Element:
		for _, v := range slice.([]nmap.Element) {
			s = append(s, v)
		}
	}
	return s
}
