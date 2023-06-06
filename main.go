package main

import (
	"crypto/tls"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/cxpsemea/CxSASTClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

const (
	matchNodeCountDeviation = 1
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	logger.Info("Starting")

	xml_report := os.Args[1]
	cx1_scan_id := os.Args[2]
	base_url := os.Args[3]
	iam_url := os.Args[4]
	tenant := os.Args[5]
	api_key := os.Args[6]

	proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	httpClient := &http.Client{}
	//httpClient.Transport = transport

	cx1client, err := Cx1ClientGo.NewAPIKeyClient(httpClient, base_url, iam_url, tenant, api_key, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err.Error())
	}

	var sastclient CxSASTClientGo.SASTClient

	var xml_results []CxSASTClientGo.ScanResult
	fileContents, err := os.ReadFile(xml_report)
	if err != nil {
		logger.Fatalf("Failed to read %v: %s", xml_report, err)
	}

	xml_results, err = sastclient.GetResultsFromXML(fileContents)
	if err != nil {
		logger.Fatalf("Failed to parse results from xml: %s", err)
	}
	logger.Infof("There were %d findings parsed from %v", len(xml_results), xml_report)

	for r := range xml_results {
		severity := strings.ToUpper(xml_results[r].Severity)
		if severity == "INFORMATION" {
			severity = "INFO"
		}
		xml_results[r].Severity = severity

		for n := range xml_results[r].Nodes {
			xml_results[r].Nodes[n].FileName = "/" + xml_results[r].Nodes[n].FileName
		}
	}

	scan, err := cx1client.GetScanByID(cx1_scan_id)
	if err != nil {
		logger.Fatalf("Failed to get scan with id %v", cx1_scan_id)
	}

	result_count, err := cx1client.GetScanResultsCountByID(scan.ScanID)
	if err != nil {
		logger.Fatalf("Failed to get count of scan results for scan %v: %s", scan.ScanID, err)
	}
	results, err := cx1client.GetScanResultsByID(scan.ScanID, result_count)
	if err != nil {
		logger.Fatalf("Failed to get all scan results for scan %v: %s", scan.ScanID, err)
	}
	logger.Infof("There are %d findings in Cx1 scan %v\n", len(results), scan.ScanID)

	logger.Info("Comparing results")
	cx1_updates := getMatchUpdates(logger, xml_results, 1, results, scan.ProjectID)

	if len(cx1_updates) > 0 {
		err = cx1client.AddResultsPredicates(cx1_updates)
		if err != nil {
			logger.Errorf("Failed to update results predicates: %s", err)
		}
	}
}

func getMatchUpdates(logger *logrus.Logger, sast_results []CxSASTClientGo.ScanResult, sast_scanID uint64, cx1_results []Cx1ClientGo.ScanResult, cx1_projectID string) []Cx1ClientGo.ResultsPredicates {
	logger.Debugf("Comparing %d SAST results with %d Cx1 results", len(sast_results), len(cx1_results))
	predicates := make([]Cx1ClientGo.ResultsPredicates, 0)
	for _, sastresult := range sast_results {
		for _, cx1result := range cx1_results {
			if scanResultsMatch(logger, sastresult, cx1result) {
				// is the current state different?
				if sastresult.Severity != cx1result.Severity || sastresult.State != cx1result.State {
					logger.Infof(" - Updating cx1 finding: %v - %v - %v [%d] in project %v", cx1result.Data.LanguageName, cx1result.Data.Group, cx1result.Data.QueryName, cx1result.SimilarityID, cx1_projectID)
					logger.Debugf(" - - Severity from XML: %v vs %v", sastresult.Severity, cx1result.Severity)
					logger.Debugf(" - - State from XML:    %v vs %v", sastresult.State, cx1result.State)

					predicates = append(predicates, Cx1ClientGo.ResultsPredicates{
						PredicateID:  "",
						SimilarityID: cx1result.SimilarityID,
						ProjectID:    cx1_projectID,
						State:        sastresult.State,
						Comment:      "",
						Severity:     sastresult.Severity,
						CreatedBy:    "",
						CreatedAt:    "",
					})
				} else {
					logger.Infof(" - Cx1 finding already matches SAST: %v - %v - %v [%d] in project %v", cx1result.Data.LanguageName, cx1result.Data.Group, cx1result.Data.QueryName, cx1result.SimilarityID, cx1_projectID)
				}

			}
		}
	}

	return predicates
}

func scanResultsMatch(logger *logrus.Logger, sast CxSASTClientGo.ScanResult, cx1 Cx1ClientGo.ScanResult) bool {
	fails := 0

	if sast.Language != cx1.Data.LanguageName || sast.Group != cx1.Data.Group || sast.QueryName != cx1.Data.QueryName {
		logger.Tracef("   - Language/Group/Query doesn't match")
		return false
	}

	if sast.Nodes[0].FileName != cx1.Data.Nodes[0].FileName {
		fails++
		logger.Tracef("   - Node[0] filename %v doesn't match %v", sast.Nodes[0].FileName, cx1.Data.Nodes[0].FileName)
	}
	if sast.Nodes[0].Line != cx1.Data.Nodes[0].Line {
		fails++
		logger.Tracef("   - Node[0] line %d doesn't match %d", sast.Nodes[0].Line, cx1.Data.Nodes[0].Line)
	}

	sast_l := len(sast.Nodes) - 1
	cx1_l := len(cx1.Data.Nodes) - 1

	if math.Abs((float64)(sast_l-cx1_l)) > matchNodeCountDeviation {
		return false
	}

	if sast.Nodes[sast_l].FileName != cx1.Data.Nodes[cx1_l].FileName {
		fails++
		logger.Tracef("   - Node[%d] filename %v doesn't match Node[%d] %v", sast_l, sast.Nodes[sast_l].FileName, cx1_l, cx1.Data.Nodes[cx1_l].FileName)
	}
	if sast.Nodes[sast_l].Line != cx1.Data.Nodes[cx1_l].Line {
		fails++
		logger.Tracef("   - Node[%d] line %d doesn't match Node[%d] %d", sast_l, sast.Nodes[sast_l].Line, cx1_l, cx1.Data.Nodes[cx1_l].Line)
	}

	if sast.QueryName != cx1.Data.QueryName {
		fails++
		logger.Tracef("   - Query Name %v doesn't match %v", sast.QueryName, cx1.Data.QueryName)
	}

	logger.Tracef("   - %d", fails)

	return fails <= 1
}
