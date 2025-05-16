package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergeCommand_Basic(t *testing.T) {
	testdataDir := filepath.Join("..", "testdata")
	outputFile := filepath.Join(os.TempDir(), "sbomctl-merge-test.json")
	defer os.Remove(outputFile)

	// Prepare args: merge sbom1.json sbom2.json -o <outputFile>
	args := []string{
		"merge",
		filepath.Join(testdataDir, "sbom1.json"),
		filepath.Join(testdataDir, "sbom2.json"),
		"-o",
		outputFile,
	}

	// Call the merge command (assume rootCmd is defined in root.go)
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("merge command failed: %v", err)
	}

	// Check that output file was created and is not empty
	info, err := os.Stat(outputFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Errorf("output file is empty")
	}
}
