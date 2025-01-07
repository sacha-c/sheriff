package repo

const VulnerabilityIssueTitle = "Sheriff - 🚨 Vulnerability report"

type PlatformType string

const (
	Gitlab PlatformType = "gitlab"
	Github PlatformType = "github"
)

type Project struct {
	ID       int
	Name     string
	Path     string
	WebURL   string
	RepoUrl  string
	Platform string
}

type Issue struct {
	ID       int
	Title    string
	WebURL   string
	Open     bool
	Platform string
}

// IService is the interface of the GitLab service as needed by sheriff
type IService interface {
	GetProjectList(paths []string) (projects []Project, warn error)
	CloseVulnerabilityIssue(project Project) error
	OpenVulnerabilityIssue(project Project, report string) (*Issue, error)
}
