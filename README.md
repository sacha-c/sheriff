<p align="center">
  <img alt="sheriff-logo" width="150" src="./assets/sheriff.png">
</p>


# Sheriff

Sheriff is a tool to scan repositories and generate security reports.

- [Quick Usage](#quick-usage)
- [How it works](#how-it-works)
  - [Issue in the affected repository](#issue-in-the-affected-repository)
  - [Report message](#report-message)
  - [Specific repository message](#specific-repository-message)
- [Installation](#installation)
  - [Docker](#docker)
  - [Manual installation](#manual-installation)
- [Configuration](#configuration)
  - [CLI flags](#cli-flags)
  - [Environment variables](#environment-variables)
  - [Configuration file](#configuration-file)
  - [Configuration options](#configuration-options)
    - [Miscellaneous](#miscellaneous)
      - [config](#config)
      - [verbose](#verbose)
    - [Scanning](#scanning)
      - [targets](#targets)
    - [Reporting](#reporting)
      - [report to issue](#report-to-issue)
      - [report to email (TODO #12)](#report-to-email-todo-12)
      - [report to slack channels](#report-to-slack-channels)
      - [enable project report to](#enable-project-report-to)
      - [silent](#silent)
    - [Tokens](#tokens)
      - [gitlab token](#gitlab-token)
      - [slack token](#slack-token)
- [Supported platforms](#supported-platforms)
  - [Source code hosting services](#source-code-hosting-services)
  - [Messaging services](#messaging-services)
  - [Scanners](#scanners)
- [Usage in CI](#usage-in-ci)
  - [In Gitlab](#in-gitlab)
- [Contributors ✨](#contributors-)

## Quick Usage

```sh
sheriff patrol --target gitlab://your-namespace-or-group --report-to-issue
```

## How it works

Sheriff analyzes repositories in source code repository hosting services (such as GitLab) looking for vulnerabilities
in the dependencies of the scanned repositories. Sheriff uses one or several third-party scanners to detect these vulnerabilities, and aggregates them into its reports. See a list of supported platforms and scanners in the [section below](#supported-platforms).

Sheriff is best used for analyzing vulnerabilities in bulk, regularly scanning groups of repositories to provide an overview of which vulnerabilities affect them. For that, Sheriff provides different types of reports, and it can publish them to different platforms such as GitLab (see [supported platforms section](#supported-platforms)).

### Issue in the affected repository

Sheriff will keep an open issue in each one of the analyzed repositories, providing a detailed report of which vulnerabilities have been found by its scanners.

<img width="600" alt='issue-report' src='./assets/issue-report.png'>

### Report message

Sheriff will post a message to a messaging service with an overview of the analyzed repositories and the vulerabilities detected. This message is intended to provide a generic overview to those in charge of security to oversee the state of a given group of repositories.

<img width='400' alt='msg-report' src='assets/report-msg.png'>

### Specific repository message

Project teams can also be informed regularly by Sheriff (if they want to) by configuring a channel to which Sheriff should report its findings of a given repository. The message generated by Sheriff will be slightly different, and will contain only information relevant for the repository maintainers.

<img width='400' alt='repo-report' src='assets/report-repo.png'>

## Installation

### Docker

The easiest way to run Sheriff is through docker:

```sh
docker pull elementsinteractive/sheriff
docker run elementsinteractive/sheriff --help
```

### Manual installation

> [!NOTE]  
> If you install Sheriff manually, you will need to ensure that all the scanners used by it are available in your system

You can install Sheriff yourself by installing its dependencies, and then either downloading the binary from the [GitHub Releases page](https://github.com/elementsinteractive/sheriff/releases) or building Sheriff from source.

```sh
brew install osv-scanner
git clone git@github.com:elementsinteractive/sheriff.git
cd sheriff
go install .
```

## Configuration

Sheriff can be configured in a few different ways:

### CLI flags

The most complete way is through CLI flags. See `sheriff patrol --help` for the full list of available options.

### Environment variables

For specific sensitive configuration keys such as API tokens, Sheriff can read them from environmental variables.
Only the **Tokens** section of configuration parameters are supported for this (see `sheriff patrol --help` for the full list).

This is the case for `GITLAB_TOKEN` & `SLACK_TOKEN` for example.

### Configuration file

Sheriff also supports configuration through a TOML config file.
Only the **Reporting** and **Scanning** sections of configuration parameters are supported for this (see `sheriff patrol --help` for the full list).

In this case you may choose to create a config file such as the following:

```toml
targets = ["namespace/group", "namespace/group/cool-repo"]
[report.to]
slack-channel = "sheriff-report-test"
issue = true
```

And if you wish to specify a different file, you can do so with `sheriff patrol --config your-config-file.toml`.

> [!NOTE]
> When using several types of configurations at once there is an order of preference: **cli flags** > **env vars** > **config file**

### Configuration options

#### Miscellaneous

##### config

| CLI options | File config |
|---|---|
| `--config` | - |

Sets the path of your sheriff configuration file

##### verbose

| CLI options | File config |
|---|---|
| `--verbose`/`-v` | - |

Sets the log level to verbose

#### Scanning

##### targets

| CLI options | File config |
|---|---|
| (repeatable) `--target` | `targets` |

Sets the list of groups and projects to be scanned.
The expected format of a target is `platform://path/to/your/group-or-project`

For example:
`--target gitlab://namespace/group --target github://organization/project`

#### Reporting

##### report to issue

| CLI options | File config |
|---|---|
| `--report-to-issue` | <code>[report.to]<br>issue</code> |

Enables reporting to an issue on the project's platform

##### report to email (TODO #12)

| CLI options | File config |
|---|---|
| (repeatable) `--report-to-email` | <code>[report.to]<br>emails</code> |

Sets the list of email to which a full scan report should be sent

##### report to slack channels

| CLI options | File config |
|---|---|
| (repeatable) `--report-to-slack-channels` | <code>[report.to]<br>slack-channels</code> |

##### enable project report to

| CLI options | File config |
|---|---|
| `--report-to-enable-project-report-to` | <code>[report.to]<br>enable-project-report-to</code> |

Enable project-level configuration `report-to` to allow projects to control where their individual reports are sent

##### silent

| CLI options | File config |
|---|---|
| `--report-silent` | <code>[report]<br>silent</code> |

Disable printing the report in the bash output

#### Tokens

##### gitlab token

| ENV VAR |
|---|
| `$GITLAB_TOKEN` |

Sets the token to be used when fetching projects from gitlab

##### slack token

| ENV VAR |
|---|
| `$SLACK_TOKEN` |

Sets the token to be used when reporting the security report on slack

## Supported platforms

### Source code hosting services

- [x] [GitLab](https://gitlab.com)
- [ ] [GitHub](https://github.com) ([#9](https://github.com/elementsinteractive/sheriff/issues/9))

### Messaging services

- [x] [Slack](http://slack.com)
- [ ] Email ([#12](https://github.com/elementsinteractive/sheriff/issues/12))

### Scanners

- [x] [OSV-Scanner](https://github.com/google/osv-scanner)
- [ ] [Trivy](https://github.com/aquasecurity/trivy)

## Usage in CI

Sheriff was designed so it could be run as part of a CI pipeline.

### In Gitlab

To run sheriff on Gitlab, we suggest the following set-up:
1. Create a repostory which will contain your CI runner, you can call it `sheriff-runner` for example
2. Create a CI file in this repository which extends from our template
    ```yaml
    include:
      - remote: 'https://raw.githubusercontent.com/elementsinteractive/sheriff/refs/tags/v0.22.2/gitlab/templates/sheriff.gitlab-ci.yml'

    sheriff:
      extends: .sheriff
    ```
3. Go to **Build** -> **Pipeline schedules** -> **New schedule**
   a. Add a name & a preferred cron interval. We prefer a weekly scan such as `0 7 * * 1` (every Monday at 7am)
   b. Add a **Variable** Variable named `SHERIFF_CLI_ARGS` which extra CLI arguments you wish to add (see CLI configuration section)
   c. Add a **File** Variable named `SHERIFF_CONFIG` containing your sheriff configuration (see file configuration section)
4. Go to **Settings** -> **CI/CD** -> **Variables**
   a. If scanning gitlab projects, add your gitlab token in **GITLAB_TOKEN** with *Protected*, *Masked*, *Hidden*
   b. If publishing reports to slack, add your slack token in **SLACK_TOKEN** with *Protected*, *Masked*
5. Test your pipeline by going to **Build** -> **Pipeline schedules** & clicking the play button on your pipline
5. Enjoy! Your pipeline should now run & scan your projects on a weekly basis 😀

We have a gitlab template set up for convenience, which runs sheriff with a set of configurable options.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/sacha-c"><img src="https://avatars.githubusercontent.com/u/3247529?v=4?s=50" width="50px;" alt="Sacha Brouté"/><br /><sub><b>Sacha Brouté</b></sub></a><br /><a href="https://github.com/elementsinteractive/sheriff/commits?author=sacha-c" title="Code">💻</a> <a href="#design-sacha-c" title="Design">🎨</a> <a href="#ideas-sacha-c" title="Ideas, Planning, & Feedback">🤔</a> <a href="#maintenance-sacha-c" title="Maintenance">🚧</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/scastlara"><img src="https://avatars.githubusercontent.com/u/7606872?v=4?s=50" width="50px;" alt="Sergio Castillo"/><br /><sub><b>Sergio Castillo</b></sub></a><br /><a href="https://github.com/elementsinteractive/sheriff/commits?author=scastlara" title="Code">💻</a> <a href="#ideas-scastlara" title="Ideas, Planning, & Feedback">🤔</a> <a href="#maintenance-scastlara" title="Maintenance">🚧</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/jbozanowski"><img src="https://avatars.githubusercontent.com/u/114900?v=4?s=50" width="50px;" alt="Jakub Bożanowski"/><br /><sub><b>Jakub Bożanowski</b></sub></a><br /><a href="#ideas-jbozanowski" title="Ideas, Planning, & Feedback">🤔</a> <a href="#design-jbozanowski" title="Design">🎨</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
