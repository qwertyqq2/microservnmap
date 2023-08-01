package parser

import (
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/Ullaakut/nmap/v3"
)

var testXML = `
<port portid="631" protocol="tcp">
                  <owner name=""></owner>
                  <service devicetype="" extrainfo="" highver="" hostname="" lowver="" method="probed" name="ipp" ostype="" product="CUPS" proto="" rpcnum="" servicefp="" tunnel="" version="2.4" conf="10">
                      <cpe>cpe:/a:apple:cups:2.4</cpe>
                  </service>
                  <state state="open" reason="syn-ack" reason_ip="" reason_ttl="0"></state>
                  <script id="http-server-header" output="CUPS/2.4 IPP/2.1">
                      <elem>CUPS/2.4 IPP/2.1</elem>
                  </script>
                  <script id="vulners" output="&#xA;  cpe:/a:apple:cups:2.4: &#xA;    &#x9;CVE-2022-26691&#x9;7.2&#x9;https://vulners.com/cve/CVE-2022-26691&#xA;    &#x9;OSV:CVE-2022-26691&#x9;0.0&#x9;https://vulners.com/osv/OSV:CVE-2022-26691">
                      <table key="cpe:/a:apple:cups:2.4">
                          <table>
                              <elem key="cvss">1</elem>
                              <elem key="id">id1</elem>
                              <elem key="type">cve</elem>
                              <elem key="is_exploit">false</elem>
                          </table>
                          <table>
                              <elem key="cvss">2</elem>
                              <elem key="id">id2</elem>
                              <elem key="type">osv</elem>
                              <elem key="is_exploit">false</elem>
                          </table>
					 <table>
                              <elem key="cvss">3</elem>
                              <elem key="id">id3</elem>
                              <elem key="type">osv</elem>
                              <elem key="is_exploit">false</elem>
                          </table>
					 <table>
                              <elem key="cvss">4</elem>
                              <elem key="id">id4</elem>
                              <elem key="type">osv</elem>
                              <elem key="is_exploit">false</elem>
                          </table>
					 <table>
                              <elem key="cvss">5</elem>
                              <elem key="id">id5</elem>
                              <elem key="type">osv</elem>
                              <elem key="is_exploit">false</elem>
                          </table>
					 <table>
                              <elem key="cvss">6</elem>
                              <elem key="id">id6</elem>
                              <elem key="type">osv</elem>
                              <elem key="is_exploit">false</elem>
                          </table>
                      </table>
                  </script>
              </port>
`

func TestParse(t *testing.T) {
	var port nmap.Port

	err := xml.Unmarshal([]byte(testXML), &port)
	if err != nil {
		t.Fatal(err)
	}

	vulns := FindVulnsFromPort(port)
	n := len(vulns) - 1

	for i, v := range vulns {
		if v.Identifier != fmt.Sprintf("id%d", n-i+1) {
			t.Fatal("neq id vuln")
		}
		if v.CvssScore != float32(n-i+1) {
			t.Fatal("neq score")
		}
	}

}
