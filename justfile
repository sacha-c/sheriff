set dotenv-load := true

run *ARGS:
    GITLAB_TOKEN=$GITLAB_TOKEN go run . {{ARGS}}

alias t := test
test:
    go test ./...
