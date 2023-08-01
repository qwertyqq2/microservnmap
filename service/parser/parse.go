package parser

import (
	"github.com/Ullaakut/nmap/v3"
	"github.com/qwertyqq2/microservTask/proto"
	"github.com/qwertyqq2/microservTask/utils"
)

func FindVulnsFromPort(port nmap.Port) []*proto.Vulnerability {
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
				tempID = ""
				tempCCVS = ""
			}
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
