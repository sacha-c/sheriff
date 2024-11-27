## v0.17.3 (2024-11-27)

### CI

- add releases and more tests

## v0.17.2 (2024-11-27)

### Fix

- app version 0.17.1

## v0.17.1 (2024-11-27)

### CI

- add golangci-lint

## v0.17.0 (2024-11-27)

### Feat

- warning errors to bubble up as cli exit code
- beautify GitLab report with reason and some disaclaimers
- acknowledge vulnerabilities
- report to individual slack channels
- scan groups and or projects
- config file and refactor
- adding structured logging to zerolog calls
- use context with timeout for shell commands
- fetch group projects with pagination
- testing flag to enable public channels
- improve cli with better flags and specific command
- tests for the git service
- tests for the main scan method
- coverage ignore functionality
- add slack service tests
- add gitlab service tests
- Add fix available to the vulnerability and the report
- Severity categories and some tests
- gitlab report slight from custom report
- slack message format slight improvement
- add custom report format
- support paginating slack channels
- support scanning subgroups
- add ci
- initial implementation
- initial commit

### Fix

- show only date in GL report header
- report slack project channel flag boolean
- oops, removing unnecessary file
- separate logging from messaging to the user
- removing pointer to a slice
- slack message limitations
- docker image with more functionality for gitlab
- making some stuff private
- vulnerability issue title
- fix version bump in main.go again
- version bump in main.go
- had dyslexia some with available fix, is now fixed PR this
- group vulnerabilities by categories defined directly from osvss
- incorrect warning message was missing one param
- sort vulnerabilities by CVSS score within a group casting to floats
- report is a double reference in osv.Scan
- do not close inexistant issue
- fix docker

### Refactor

- remove gitlab project pointers
- remove unnecessary pointer to report in slice
- simplify group fetching
- make vulnScanners format their own report
- change name of some packages, and merge report packages
- remove unneded `newService` private trick
- test osv scan and refactor shell stuff
- gitlab and slack service and better error handling

### Perf

- use goroutines and channels to run scan in parallel
- use goroutines for creating GitLab issues

### CI

- add version bumping with commitizen
- add workflows
- fix docker again
- add code coverage in gitlab-ci
- improve docker by not installing osv-scanner
- improve ci job definition

### Docs

- add godoc comments to all exported functions

### Technical

- add flag to enable project slack reports
- add warning when no projects to report
- add logs for sheriff configuration
- log warnings when project-config has unrecognized keys
- sheriff is patrolling
- sheriff is in town
- improve docker image
- minor improvements to ci job and sorting
- post multiple project reports
- improve logging

### Tests

- add test for gitlab issue url
- test publish to slack
- add tests for console publisher
- move to testify assertions
