package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

func TestInspectCommand(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-inspect-test")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM file
	testSBOMPath := filepath.Join(testDir, "test-sbom.json")

	// Create a test SBOM with known components and dependencies
	testBom := cyclonedx.NewBOM()
	testBom.SerialNumber = "urn:uuid:test-uuid"
	testBom.BOMFormat = "CycloneDX"
	testBom.SpecVersion = cyclonedx.SpecVersion1_4
	testBom.Version = 1

	// Add metadata
	testBom.Metadata = &cyclonedx.Metadata{
		Timestamp: "2023-01-01T12:00:00Z",
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					BOMRef:    "test-tool",
					Name:      "Test Tool",
					Version:   "1.0.0",
					Publisher: "Test Vendor",
					Type:      cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}

	// Add components of different types
	testBom.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "pkg:npm/library-component@1.0.0",
			Name:    "library-component",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			BOMRef:  "pkg:npm/framework-component@2.0.0",
			Name:    "framework-component",
			Version: "2.0.0",
			Type:    cyclonedx.ComponentTypeFramework,
		},
		{
			BOMRef:  "pkg:npm/application-component@3.0.0",
			Name:    "application-component",
			Version: "3.0.0",
			Type:    cyclonedx.ComponentTypeApplication,
		},
	}

	// Add dependencies
	testBom.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref: "pkg:npm/application-component@3.0.0",
			Dependencies: &[]string{
				"pkg:npm/framework-component@2.0.0",
				"pkg:npm/library-component@1.0.0",
			},
		},
		{
			Ref: "pkg:npm/framework-component@2.0.0",
			Dependencies: &[]string{
				"pkg:npm/library-component@1.0.0",
			},
		},
	}

	// Create a buffer to capture the output
	var outputBuffer bytes.Buffer

	// Call the formatSBOMInfo function directly
	formatSBOMInfo(&outputBuffer, testBom, testSBOMPath)

	// Get the output as a string
	output := outputBuffer.String()

	// Verify the output contains expected information
	expectedStrings := []string{
		"File:",
		"SBOM Format:",
		"Spec Version:",
		"Serial Number:",
		"Version:",
		"Timestamp:",
		"Tools:",
		"Test Tool",
		"Total Components:",
		"Component Types:",
		"- application:",
		"- framework:",
		"- library:",
		"library-component",
		"framework-component",
		"application-component",
		"Total Dependencies:",
		"Dependencies with dependsOn:",
		"Max dependsOn count:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', but it did not.\nOutput: %s", expected, output)
		}
	}
}

func TestInspectCommandNoComponents(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-inspect-test-no-components")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM file
	testSBOMPath := filepath.Join(testDir, "test-sbom-no-components.json")

	// Create a test SBOM with no components or dependencies
	testBom := cyclonedx.NewBOM()
	testBom.SerialNumber = "urn:uuid:test-uuid-no-components"
	testBom.BOMFormat = "CycloneDX"
	testBom.SpecVersion = cyclonedx.SpecVersion1_4
	testBom.Version = 1

	// Create a buffer to capture the output
	var outputBuffer bytes.Buffer

	// Call the formatSBOMInfo function directly
	formatSBOMInfo(&outputBuffer, testBom, testSBOMPath)

	// Get the output as a string
	output := outputBuffer.String()

	// Verify the output contains expected information
	expectedStrings := []string{
		"File:",
		"SBOM Format:",
		"Spec Version:",
		"Serial Number:",
		"Version:",
		"Components:",
		"No components found",
		"Dependencies:",
		"No dependencies found",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', but it did not.\nOutput: %s", expected, output)
		}
	}
}
