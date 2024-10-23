package scanner

import (
	"fmt"
	"log"
	"os"
	"securityscanner/internal/git"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/osv"

	gogitlab "github.com/xanzy/go-gitlab"
)

const TempScanDir = "tmp_scans"

type Report struct {
	Project      *gogitlab.Project
	IsVulnerable bool
	Report       string
}

func Scan(namespace string) (reports []Report) {
	// Create a temporary directory to store the scans
	err := os.MkdirAll(TempScanDir, os.ModePerm)
	if err != nil {
		log.Panicf("Could not create temporary directory %v", err)
	}
	defer os.RemoveAll(TempScanDir)
	log.Default().Printf("Created temporary directory %v", TempScanDir)

	log.Default().Print("Getting the list of projects to scan...")
	projects := gitlab.GetProjectList(namespace)

	for _, project := range projects {
		if report, err := scanProject(project); err != nil {
			log.Default().Printf("Failed to scan project %v, skipping. %v", project.Name, err)
		} else {
			reports = append(reports, report)
		}
	}

	return
}

func scanProject(project *gogitlab.Project) (report Report, err error) {
	log.Default().Printf("Scanning project %v", project.Name)

	dir, err := os.MkdirTemp(TempScanDir, fmt.Sprintf("%v-", project.Name))
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(dir)

	// Clone the project
	log.Default().Printf("Cloning project in %v", dir)
	if err = git.Clone(dir, project.HTTPURLToRepo); err != nil {
		log.Default().Printf("Failed to clone project %v", err)
		return
	}

	// Scan the project
	isVulnerable, osv_report, err := osv.Scan(dir)
	if err != nil {
		log.Default().Printf("Something went wrong when running osv-scanner: %v", err)
		return
	}

	log.Default().Printf("Finished scanning project %v\n", project.Name)

	report = Report{
		Project:      project,
		IsVulnerable: isVulnerable,
		Report:       osv_report,
	}

	return
}
