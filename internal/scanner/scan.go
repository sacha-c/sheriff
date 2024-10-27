package scanner

import (
	"fmt"
	"os"
	"securityscanner/internal/git"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/osv"

	"github.com/rs/zerolog/log"
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
		log.Panic().Err(err).Msg("Could not create temporary directory")
	}
	defer os.RemoveAll(TempScanDir)
	log.Info().Msgf("Created temporary directory %v", TempScanDir)

	log.Info().Msg("Getting the list of projects to scan...")
	projects := gitlab.GetProjectList(namespace)

	for _, project := range projects {
		if report, err := scanProject(project); err != nil {
			log.Err(err).Msgf("Failed to scan project %v, skipping", project.Name)
		} else {
			reports = append(reports, report)
		}
	}

	return
}

func scanProject(project *gogitlab.Project) (report Report, err error) {
	log.Info().Msgf("Scanning project %v", project.Name)

	dir, err := os.MkdirTemp(TempScanDir, fmt.Sprintf("%v-", project.Name))
	if err != nil {
		log.Panic().Err(err)
	}
	defer os.RemoveAll(dir)

	// Clone the project
	log.Info().Msgf("Cloning project in %v", dir)
	if err = git.Clone(dir, project.HTTPURLToRepo); err != nil {
		log.Err(err).Msg("Failed to clone project")
		return
	}

	// Scan the project
	isVulnerable, osv_report, err := osv.Scan(dir)
	if err != nil {
		log.Err(err).Msg("Something went wrong when running osv-scanner")
		return
	}

	log.Info().Msgf("Finished scanning project %v", project.Name)

	report = Report{
		Project:      project,
		IsVulnerable: isVulnerable,
		Report:       osv_report,
	}

	return
}
