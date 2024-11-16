package publish

import (
	"fmt"
	"sheriff/internal/scanner"
	"strings"

	"github.com/rs/zerolog/log"
)

// PublishToConsole prints reports to the terminal console.
// If silentReport is true, the report will be logged as debug instead of printed to the console.
func PublishToConsole(scanReports []scanner.Report, silentReport bool) {
	r := formatReportsMessageForConsole(scanReports)
	if silentReport {
		log.Debug().Str("report", r)
	} else {
		fmt.Println(r)
	}
}

// formatReportsMessageForConsole formats the scan reports into a string message
// ready to be sent to the console.
func formatReportsMessageForConsole(scanReports []scanner.Report) string {
	var r strings.Builder

	if len(scanReports) == 0 {
		r.WriteString("No vulnerabilities found in the scanned projects.")
	}

	r.WriteString("\nVulnerability Report:\n")
	r.WriteString(fmt.Sprintf("Total number of projects scanned: %v\n", len(scanReports)))
	for _, report := range scanReports {
		r.WriteString(fmt.Sprintln("---------------------------------"))
		r.WriteString(fmt.Sprintf("%v\n", report.Project.PathWithNamespace))
		r.WriteString(fmt.Sprintf("\tProject URL: %v\n", report.Project.WebURL))
		r.WriteString(fmt.Sprintf("\tNumber of vulnerabilities: %v\n", len(report.Vulnerabilities)))
	}
	return r.String()
}
