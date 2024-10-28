package scanner

import (
	"errors"
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

func Scan(groupPath []string, svc *gitlab.Service) (reports []Report, err error) {
	// Create a temporary directory to store the scans
	err = os.MkdirAll(TempScanDir, os.ModePerm)
	if err != nil {
		return nil, errors.New("could not create temporary directory")
	}
	defer os.RemoveAll(TempScanDir)
	log.Info().Msgf("Created temporary directory %v", TempScanDir)

	log.Info().Msg("Getting the list of projects to scan...")
	projects, err := svc.GetProjectList(groupPath)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("could not get project list of group %v", groupPath), err)
	}

	for _, project := range projects {
		log.Info().Msgf("Scanning project %v", project.Name)
		if report, err := scanProject(project); err != nil {
			log.Err(err).Msgf("Failed to scan project %v, skipping", project.Name)
		} else {
			reports = append(reports, *report)
		}
	}

	return
}

func scanProject(project *gogitlab.Project) (report *Report, err error) {
	dir, err := os.MkdirTemp(TempScanDir, fmt.Sprintf("%v-", project.Name))
	if err != nil {
		return nil, errors.Join(errors.New("failed to create project temporary directory"), err)
	}
	defer os.RemoveAll(dir)

	// Clone the project
	log.Info().Msgf("Cloning project in %v", dir)
	if err = git.Clone(dir, project.HTTPURLToRepo); err != nil {
		return nil, errors.Join(errors.New("failed to clone project"), err)
	}

	// Scan the project
	isVulnerable, osv_report, err := osv.Scan(dir)
	if err != nil {
		return nil, errors.Join(errors.New("failed to run osv-scanner"), err)
	}

	log.Info().Msgf("Finished scanning project %v", project.Name)

	report = &Report{
		Project:      project,
		IsVulnerable: isVulnerable,
		Report:       osv_report,
	}

	return
}
