package osv

import (
	"io"
	"os"
	"testing"
)

func TestReadOSVJson(t *testing.T) {
	jsonFile, err := os.Open("testdata/osv-output.json")
	if err != nil {
		t.Fatal(err)
	}

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatal(err)
	}

	got := new(Report)
	err = readOSVJson(byteValue, &got)

	if err != nil {
		t.Fatal(err)
	}

	if len(got.Results) != 1 {
		t.Errorf("Expected 1 result, got %v", len(got.Results))
	}

	if len(got.Results[0].Packages) != 2 {
		t.Errorf("Expected 2 packages, got %v", len(got.Results[0].Packages))
	}
	firstPackage := got.Results[0].Packages[0]

	if len(firstPackage.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %v", len(firstPackage.Vulnerabilities))
	}
}
