package main

import (
	"flag"
	"math"
	"net/http"
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

var QueryMap map[uint64]uint64

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	logger.Info("Starting")

	APIKey := flag.String("apikey", "", "CheckmarxOne API Key (if not using client id/secret)")
	ClientID := flag.String("client", "", "CheckmarxOne Client ID (if not using API Key)")
	ClientSecret := flag.String("secret", "", "CheckmarxOne Client Secret (if not using API Key)")
	Cx1URL := flag.String("cx1url", "", "CheckmarxOne platform URL, eg: eu.ast.checkmarx.net")
	IAMURL := flag.String("iamurl", "", "CheckmarxOne IAM URL, eg: eu.iam.checkmarx.net")
	Tenant := flag.String("tenant", "", "CheckmarxOne tenant name")
	Debug := flag.Bool("debug", false, "Additional debug output")

	Cx1ScanID := flag.String("scanid", "", "CheckmarxOne Scan ID destination for update")
	XMLReport := flag.String("xml", "", "Path to CxSAST XML report")

	flag.Parse()

	if (*APIKey == "" && (*ClientID == "" || *ClientSecret == "")) || *Cx1URL == "" || *IAMURL == "" || *Tenant == "" || *Cx1ScanID == "" || *XMLReport == "" {
		logger.Info("The purpose of this tool is to update findings in a CheckmarxOne SAST scan based on a CxSAST Scan XML report.")
		logger.Fatal("Some parameters were not provided. For a list of parameters run: XMLtoCx1 -h")
	}

	if *Debug {
		logger.SetLevel(logrus.DebugLevel)
	}

	/*
		proxyURL, _ := url.Parse("http://127.0.0.1:8080")
		transport := &http.Transport{}
		transport.Proxy = http.ProxyURL(proxyURL)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	*/

	httpClient := &http.Client{}
	//httpClient.Transport = transport

	var cx1client *Cx1ClientGo.Cx1Client
	var err error
	if *APIKey != "" {
		cx1client, err = Cx1ClientGo.NewAPIKeyClient(httpClient, *Cx1URL, *IAMURL, *Tenant, *APIKey, logger)
	} else {
		cx1client, err = Cx1ClientGo.NewOAuthClient(httpClient, *Cx1URL, *IAMURL, *Tenant, *ClientID, *ClientSecret, logger)
	}

	if err != nil {
		logger.Fatalf("Error creating client: %s", err.Error())
	}

	var sastclient CxSASTClientGo.SASTClient

	var xml_results []CxSASTClientGo.ScanResult
	fileContents, err := os.ReadFile(*XMLReport)
	if err != nil {
		logger.Fatalf("Failed to read %v: %s", *XMLReport, err)
	}

	xml_results, err = sastclient.GetResultsFromXML(fileContents)
	if err != nil {
		logger.Fatalf("Failed to parse results from xml: %s", err)
	}
	logger.Infof("There were %d findings parsed from %v", len(xml_results), *XMLReport)

	// change the incoming CxSAST XML data to better match Cx1 styles/formats
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

	scan, err := cx1client.GetScanByID(*Cx1ScanID)
	if err != nil {
		logger.Fatalf("Failed to get scan with id %v", *Cx1ScanID)
	}

	result_count, err := cx1client.GetScanResultsCountByID(scan.ScanID)
	if err != nil {
		logger.Fatalf("Failed to get count of scan results for scan %v: %s", scan.ScanID, err)
	}
	results, err := cx1client.GetScanResultsByID(scan.ScanID, result_count)
	if err != nil {
		logger.Fatalf("Failed to get all scan results for scan %v: %s", scan.ScanID, err)
	}
	logger.Infof("There are %d findings in Cx1 scan %v\n", len(results.SAST), scan.ScanID)

	QueryMap, err = cx1client.GetQueryMappings()
	if err != nil {
		logger.Fatalf("Failed to get query mappings from Cx1: %s", err)
	}

	logger.Info("Comparing results")
	cx1_updates := getMatchUpdates(logger, xml_results, 1, results.SAST, scan.ProjectID)

	if len(cx1_updates) > 0 {
		err = cx1client.AddSASTResultsPredicates(cx1_updates)
		if err != nil {
			logger.Errorf("Failed to update results predicates: %s", err)
		}
	}
}

func getMatchUpdates(logger *logrus.Logger, sast_results []CxSASTClientGo.ScanResult, sast_scanID uint64, cx1_results []Cx1ClientGo.ScanSASTResult, cx1_projectID string) []Cx1ClientGo.SASTResultsPredicates {
	logger.Debugf("Comparing %d SAST results with %d Cx1 results", len(sast_results), len(cx1_results))
	predicates := make([]Cx1ClientGo.SASTResultsPredicates, 0)
	missing_matches := 0
	for _, sastresult := range sast_results {
		hasMatch := false
		for _, cx1result := range cx1_results {
			if scanResultsMatch(logger, sastresult, cx1result) {
				hasMatch = true
				// is the current state different?
				if sastresult.Severity != cx1result.Severity || sastresult.State != cx1result.State {
					logger.Infof(" - Updating cx1 finding: %v - %v - %v [%v] in project %v", cx1result.Data.LanguageName, cx1result.Data.Group, cx1result.Data.QueryName, cx1result.SimilarityID, cx1_projectID)
					logger.Debugf(" - - Severity from XML: %v vs %v", sastresult.Severity, cx1result.Severity)
					logger.Debugf(" - - State from XML:    %v vs %v", sastresult.State, cx1result.State)

					predicates = append(predicates, Cx1ClientGo.SASTResultsPredicates{
						ResultsPredicatesBase: Cx1ClientGo.ResultsPredicatesBase{PredicateID: "",
							SimilarityID: cx1result.SimilarityID,
							ProjectID:    cx1_projectID,
							State:        sastresult.State,
							Comment:      "",
							Severity:     sastresult.Severity,
							CreatedBy:    "",
							CreatedAt:    ""},
					})
				} else {
					logger.Infof(" - Cx1 finding already matches SAST: %v - %v - %v [%v] in project %v", cx1result.Data.LanguageName, cx1result.Data.Group, cx1result.Data.QueryName, cx1result.SimilarityID, cx1_projectID)
					logger.Debugf(" - - Severity from XML: %v vs %v", sastresult.Severity, cx1result.Severity)
					logger.Debugf(" - - State from XML:    %v vs %v", sastresult.State, cx1result.State)
				}

				break
			}
		}

		if !hasMatch {
			logger.Infof(" - CxSAST finding %v -> %v -> %v with similarityID %d not found in Cx1", sastresult.Language, sastresult.Group, sastresult.QueryName, sastresult.SimilarityID)
			missing_matches++
		}
	}

	if missing_matches > 0 {
		logger.Warnf("%d findings from CxSAST were not found in Cx1.", missing_matches)
		logger.Warnf("This can be due to various reasons including: different presets, different engine versions, different sources scanned, different queries.")
	}

	return predicates
}

func scanResultsMatch(logger *logrus.Logger, sast CxSASTClientGo.ScanResult, cx1 Cx1ClientGo.ScanSASTResult) bool {
	fails := 0

	if QueryMap[sast.QueryID] != cx1.Data.QueryID && (!strings.EqualFold(sast.Language, cx1.Data.LanguageName) || !strings.EqualFold(sast.Group, cx1.Data.Group) || !strings.EqualFold(sast.QueryName, cx1.Data.QueryName)) {
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
