package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

func TestMergeSBOMs(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with components A and B
	sbom1 := cyclonedx.NewBOM()
	sbom1.Components = &[]cyclonedx.Component{
		{
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			Name:    "component-b",
			Version: "2.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	// Create second SBOM with components B and C
	sbom2 := cyclonedx.NewBOM()
	sbom2.Components = &[]cyclonedx.Component{
		{
			Name:    "component-b",
			Version: "2.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			Name:    "component-c",
			Version: "3.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	// Write test SBOMs to files
	if err := WriteSBOMFile(sbom1, sbom1Path); err != nil {
		t.Fatalf("Failed to write test SBOM 1: %v", err)
	}
	if err := WriteSBOMFile(sbom2, sbom2Path); err != nil {
		t.Fatalf("Failed to write test SBOM 2: %v", err)
	}

	// Test merging SBOMs
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath)
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has the expected components
	if mergedBom.Components == nil {
		t.Fatal("Merged SBOM has no components")
	}

	components := *mergedBom.Components
	if len(components) != 3 {
		t.Fatalf("Expected 3 components in merged SBOM, got %d", len(components))
	}

	// Check for expected components
	componentNames := make(map[string]bool)
	for _, c := range components {
		componentNames[c.Name] = true
	}

	expectedComponents := []string{"component-a", "component-b", "component-c"}
	for _, name := range expectedComponents {
		if !componentNames[name] {
			t.Errorf("Expected component %s in merged SBOM, but it was not found", name)
		}
	}
}

func TestMergeSBOMsWithDependencies(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-deps")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with components A and B and a dependency
	sbom1 := cyclonedx.NewBOM()
	sbom1.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-a",
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			BOMRef:  "component-b",
			Name:    "component-b",
			Version: "2.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}
	sbom1.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref: "component-a",
			Dependencies: &[]string{
				"component-b",
			},
		},
	}

	// Create second SBOM with components C and D and a dependency
	sbom2 := cyclonedx.NewBOM()
	sbom2.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-c",
			Name:    "component-c",
			Version: "3.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			BOMRef:  "component-d",
			Name:    "component-d",
			Version: "4.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}
	sbom2.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref: "component-c",
			Dependencies: &[]string{
				"component-d",
			},
		},
	}

	// Write test SBOMs to files
	if err := WriteSBOMFile(sbom1, sbom1Path); err != nil {
		t.Fatalf("Failed to write test SBOM 1: %v", err)
	}
	if err := WriteSBOMFile(sbom2, sbom2Path); err != nil {
		t.Fatalf("Failed to write test SBOM 2: %v", err)
	}

	// Test merging SBOMs
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath)
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has the expected components
	if mergedBom.Components == nil {
		t.Fatal("Merged SBOM has no components")
	}

	components := *mergedBom.Components
	if len(components) != 4 {
		t.Fatalf("Expected 4 components in merged SBOM, got %d", len(components))
	}

	// Verify the merged SBOM has the expected dependencies
	if mergedBom.Dependencies == nil {
		t.Fatal("Merged SBOM has no dependencies")
	}

	dependencies := *mergedBom.Dependencies
	if len(dependencies) != 2 {
		t.Fatalf("Expected 2 dependencies in merged SBOM, got %d", len(dependencies))
	}

	// Check for expected dependencies
	depRefs := make(map[string]bool)
	for _, d := range dependencies {
		depRefs[d.Ref] = true
	}

	expectedDeps := []string{"component-a", "component-c"}
	for _, ref := range expectedDeps {
		if !depRefs[ref] {
			t.Errorf("Expected dependency ref %s in merged SBOM, but it was not found", ref)
		}
	}
}

func TestDependencyDeduplication(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-dedup")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with component A depending on B
	sbom1 := cyclonedx.NewBOM()
	sbom1.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-a",
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			BOMRef:  "component-b",
			Name:    "component-b",
			Version: "2.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}
	sbom1.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref: "component-a",
			Dependencies: &[]string{
				"component-b",
			},
		},
	}

	// Create second SBOM with component A depending on C
	sbom2 := cyclonedx.NewBOM()
	sbom2.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-a",
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			BOMRef:  "component-c",
			Name:    "component-c",
			Version: "3.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}
	sbom2.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref: "component-a",
			Dependencies: &[]string{
				"component-c",
			},
		},
	}

	// Write test SBOMs to files
	if err := WriteSBOMFile(sbom1, sbom1Path); err != nil {
		t.Fatalf("Failed to write test SBOM 1: %v", err)
	}
	if err := WriteSBOMFile(sbom2, sbom2Path); err != nil {
		t.Fatalf("Failed to write test SBOM 2: %v", err)
	}

	// Test merging SBOMs
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath)
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has the expected components
	if mergedBom.Components == nil {
		t.Fatal("Merged SBOM has no components")
	}

	components := *mergedBom.Components
	if len(components) != 3 {
		t.Fatalf("Expected 3 components in merged SBOM, got %d", len(components))
	}

	// Verify the merged SBOM has the expected dependencies
	if mergedBom.Dependencies == nil {
		t.Fatal("Merged SBOM has no dependencies")
	}

	dependencies := *mergedBom.Dependencies
	if len(dependencies) != 1 {
		t.Fatalf("Expected 1 dependency in merged SBOM, got %d", len(dependencies))
	}

	// Check that component-a depends on both component-b and component-c
	componentADep := dependencies[0]
	if componentADep.Ref != "component-a" {
		t.Fatalf("Expected dependency ref to be component-a, got %s", componentADep.Ref)
	}

	if componentADep.Dependencies == nil {
		t.Fatal("component-a has no dependencies")
	}

	dependsOn := *componentADep.Dependencies
	if len(dependsOn) != 2 {
		t.Fatalf("Expected component-a to depend on 2 components, got %d", len(dependsOn))
	}

	// Check that component-a depends on both component-b and component-c
	expectedDeps := map[string]bool{
		"component-b": false,
		"component-c": false,
	}

	for _, dep := range dependsOn {
		expectedDeps[dep] = true
	}

	for dep, found := range expectedDeps {
		if !found {
			t.Errorf("Expected component-a to depend on %s, but it was not found", dep)
		}
	}
}
