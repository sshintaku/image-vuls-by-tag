package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	CloudType "github.com/sshintaku/cloud_types"
	"github.com/sshintaku/prisma_session"
)

func main() {
	var params = readParameters()
	session := prisma_session.Session{}
	session.CreateSession()
	imageData := session.GetDeployedImages()
	maintainerList := session.GetMaintainerList(params.RegEx, imageData)
	for _, maintainer := range maintainerList {

		result := session.GetMaintainerImages(maintainer, imageData)

		for _, item := range result {
			var overallComplianceCounter CloudType.AlarmCounter
			fmt.Println("," + item.RepoTags.Repo)
			for _, vulnerability := range item.VulnerabilityIssues {
				var flag = false
				for _, parameter := range params.AlarmLevels {
					if parameter == "critical" || parameter == "high" || parameter == "important" || parameter == "medium" || parameter == "moderate" || parameter == "low" {
						flag = true
					}
				}
				if flag {

					dateTarget := time.Now().Add(-time.Duration(params.AlarmDate)).Unix()
					if vulnerability.FixDate < dateTarget {
						fixdate := time.Unix(vulnerability.FixDate, 0)
						report := ",," + vulnerability.PackageName + "," + vulnerability.PackageVersion + "," + vulnerability.Severity + "," + vulnerability.CVE + "," + vulnerability.Link + ",\"" + vulnerability.Status + "\"," + fmt.Sprint(fixdate)
						fmt.Println(report)
						switch vulnerability.Severity {
						case "critical":
							overallComplianceCounter.Critical += 1

						case "high":
							overallComplianceCounter.High += 1

						case "important":
							overallComplianceCounter.Important += 1

						case "medium":
							overallComplianceCounter.Medium += 1

						case "moderate":
							overallComplianceCounter.Moderate += 1

						case "low":
							overallComplianceCounter.Low += 1

						}
					}
				}
			}
			report := "Summary:,,Critical: " + strconv.Itoa(overallComplianceCounter.Critical) + ",High: " + strconv.Itoa(overallComplianceCounter.High) + ",Important: " + strconv.Itoa(overallComplianceCounter.Important) + ", Moderate: " + strconv.Itoa(overallComplianceCounter.Moderate) + ", Medium: " + strconv.Itoa(overallComplianceCounter.Medium) + ",Low: " + strconv.Itoa(overallComplianceCounter.Low) + "\n"
			fmt.Println(report)

		}

	}

}

func readParameters() Parameters {
	var params Parameters
	paramBytes, err := os.ReadFile(".parameter.json")
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(paramBytes, &params)
	if len(params.AlarmLevels) == 0 {
		log.Fatalln("The alarm levels must not be empty.  There should be at least one value such as \"critical\"")
	}
	return params
}

type Parameters struct {
	AlarmLevels []string
	RegEx       string
	AlarmDate   int
}
