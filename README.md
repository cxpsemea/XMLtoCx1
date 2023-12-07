GoLang project using both CxSASTClientGo and Cx1ClientGo. 
Parses results from a provided xml report and pushes the statuses to a CheckmarxOne project/scan.

Usage: 
XMLtoCx1 -h

```
Usage of XMLtoCx1.exe:
    -apikey string
            CheckmarxOne API Key (if not using client id/secret)
    -client string
            CheckmarxOne Client ID (if not using API Key)
    -cx1url string
            CheckmarxOne platform URL, eg: eu.ast.checkmarx.net
    -debug
            Additional debug output
    -iamurl string
            CheckmarxOne IAM URL, eg: eu.iam.checkmarx.net
    -scanid string
            CheckmarxOne Scan ID destination for update
    -secret string
            CheckmarxOne Client Secret (if not using API Key)
    -tenant string
            CheckmarxOne tenant name
    -xml string
            Path to CxSAST XML report
```