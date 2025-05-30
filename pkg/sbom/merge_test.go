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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
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

func TestMergeSBOMsWithMetadataComponent(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-metadata-component")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with metadata.component
	sbom1 := cyclonedx.NewBOM()
	sbom1.Metadata = &cyclonedx.Metadata{
		Component: &cyclonedx.Component{
			BOMRef:  "component-root-1",
			Name:    "root-component-1",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeApplication,
		},
	}
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
			Ref: "component-root-1",
			Dependencies: &[]string{
				"component-a",
				"component-b",
			},
		},
	}

	// Create second SBOM with metadata.component
	sbom2 := cyclonedx.NewBOM()
	sbom2.Metadata = &cyclonedx.Metadata{
		Component: &cyclonedx.Component{
			BOMRef:  "component-root-2",
			Name:    "root-component-2",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeApplication,
		},
	}
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
			Ref: "component-root-2",
			Dependencies: &[]string{
				"component-c",
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has a metadata.component
	if mergedBom.Metadata == nil || mergedBom.Metadata.Component == nil {
		t.Fatal("Merged SBOM has no metadata.component")
	}

	// Verify the merged SBOM's metadata.component has the expected name
	if mergedBom.Metadata.Component.Name != "merged-sbom" {
		t.Fatalf("Expected merged SBOM metadata.component name to be 'merged-sbom', got '%s'", mergedBom.Metadata.Component.Name)
	}

	// Verify the merged SBOM has the expected components
	if mergedBom.Components == nil {
		t.Fatal("Merged SBOM has no components")
	}

	components := *mergedBom.Components
	// Should have 6 components: component-a, component-b, component-c, component-d, component-root-1, component-root-2
	if len(components) != 6 {
		t.Fatalf("Expected 6 components in merged SBOM, got %d", len(components))
	}

	// Check for expected components
	componentRefs := make(map[string]bool)
	for _, c := range components {
		componentRefs[c.BOMRef] = true
	}

	expectedComponents := []string{"component-a", "component-b", "component-c", "component-d", "component-root-1", "component-root-2"}
	for _, ref := range expectedComponents {
		if !componentRefs[ref] {
			t.Errorf("Expected component %s in merged SBOM, but it was not found", ref)
		}
	}

	// Verify the merged SBOM has the expected dependencies
	if mergedBom.Dependencies == nil {
		t.Fatal("Merged SBOM has no dependencies")
	}

	// Find the merged-sbom dependency
	var mergedBomDep *cyclonedx.Dependency
	for _, dep := range *mergedBom.Dependencies {
		if dep.Ref == mergedBom.Metadata.Component.BOMRef {
			mergedBomDep = &dep
			break
		}
	}

	if mergedBomDep == nil {
		t.Fatal("Merged SBOM has no dependency for the merged-sbom component")
	}

	// Verify the merged-sbom depends on both root components
	if mergedBomDep.Dependencies == nil {
		t.Fatal("merged-sbom dependency has no dependsOn")
	}

	dependsOn := *mergedBomDep.Dependencies
	if len(dependsOn) != 2 {
		t.Fatalf("Expected merged-sbom to depend on 2 components, got %d", len(dependsOn))
	}

	// Check that merged-sbom depends on both root components
	expectedDeps := map[string]bool{
		"component-root-1": false,
		"component-root-2": false,
	}

	for _, dep := range dependsOn {
		expectedDeps[dep] = true
	}

	for dep, found := range expectedDeps {
		if !found {
			t.Errorf("Expected merged-sbom to depend on %s, but it was not found", dep)
		}
	}
}

// TestMergeSBOMsWithMixedMetadataComponent tests merging SBOMs where some have metadata.component and some don't
func TestMergeSBOMsWithMixedMetadataComponent(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-mixed-metadata")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with metadata.component
	sbom1 := cyclonedx.NewBOM()
	sbom1.Metadata = &cyclonedx.Metadata{
		Component: &cyclonedx.Component{
			BOMRef:  "component-root-1",
			Name:    "root-component-1",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeApplication,
		},
	}
	sbom1.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-a",
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	// Create second SBOM without metadata.component
	sbom2 := cyclonedx.NewBOM()
	sbom2.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-b",
			Name:    "component-b",
			Version: "2.0.0",
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has a metadata.component
	if mergedBom.Metadata == nil || mergedBom.Metadata.Component == nil {
		t.Fatal("Merged SBOM has no metadata.component")
	}

	// Verify the merged SBOM has the expected components
	if mergedBom.Components == nil {
		t.Fatal("Merged SBOM has no components")
	}

	components := *mergedBom.Components
	// Should have 3 components: component-a, component-b, component-root-1
	if len(components) != 3 {
		t.Fatalf("Expected 3 components in merged SBOM, got %d", len(components))
	}

	// Check for expected components
	componentRefs := make(map[string]bool)
	for _, c := range components {
		componentRefs[c.BOMRef] = true
	}

	expectedComponents := []string{"component-a", "component-b", "component-root-1"}
	for _, ref := range expectedComponents {
		if !componentRefs[ref] {
			t.Errorf("Expected component %s in merged SBOM, but it was not found", ref)
		}
	}

	// Verify the merged SBOM has the expected dependencies
	if mergedBom.Dependencies == nil {
		t.Fatal("Merged SBOM has no dependencies")
	}

	// Verify the merged SBOM has at least one dependency
	dependencies := *mergedBom.Dependencies
	if len(dependencies) == 0 {
		t.Fatal("Merged SBOM has no dependencies")
	}
}

func TestMergeSBOMsWithCustomComponentNameAndVersion(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-custom-component")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create simple SBOMs for testing
	sbom1 := cyclonedx.NewBOM()
	sbom1.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-a",
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	sbom2 := cyclonedx.NewBOM()
	sbom2.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "component-b",
			Name:    "component-b",
			Version: "2.0.0",
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

	// Custom component name and version
	customName := "my-custom-sbom"
	customVersion := "1.2.3"

	// Test merging SBOMs with custom component name and version
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, customName, customVersion)
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has a metadata.component
	if mergedBom.Metadata == nil || mergedBom.Metadata.Component == nil {
		t.Fatal("Merged SBOM has no metadata.component")
	}

	// Verify the merged SBOM's metadata.component has the expected name
	if mergedBom.Metadata.Component.Name != customName {
		t.Fatalf("Expected merged SBOM metadata.component name to be '%s', got '%s'",
			customName, mergedBom.Metadata.Component.Name)
	}

	// Verify the merged SBOM's metadata.component has the expected version
	if mergedBom.Metadata.Component.Version != customVersion {
		t.Fatalf("Expected merged SBOM metadata.component version to be '%s', got '%s'",
			customVersion, mergedBom.Metadata.Component.Version)
	}

	// Verify the merged SBOM has the expected components
	if mergedBom.Components == nil {
		t.Fatal("Merged SBOM has no components")
	}

	components := *mergedBom.Components
	if len(components) != 2 {
		t.Fatalf("Expected 2 components in merged SBOM, got %d", len(components))
	}
}

func TestMergeSBOMsDeduplicatesToolsWithSameNameDifferentVendor(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-tools-vendor")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with a tool that has vendor information
	sbom1 := cyclonedx.NewBOM()
	sbom1.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Name:      "trivy",
					Version:   "0.61.0",
					Publisher: "aquasecurity",
					Type:      cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}
	sbom1.Components = &[]cyclonedx.Component{
		{
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	// Create second SBOM with the same tool but without vendor information
	sbom2 := cyclonedx.NewBOM()
	sbom2.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Name:    "trivy",
					Version: "0.61.0",
					Type:    cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}
	sbom2.Components = &[]cyclonedx.Component{
		{
			Name:    "component-b",
			Version: "2.0.0",
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has tools metadata
	if mergedBom.Metadata == nil || mergedBom.Metadata.Tools == nil || mergedBom.Metadata.Tools.Components == nil {
		t.Fatal("Merged SBOM has no tools metadata")
	}

	// Verify the merged SBOM has only 2 tool components (trivy and sbomctl)
	tools := *mergedBom.Metadata.Tools.Components
	if len(tools) != 2 {
		t.Fatalf("Expected 2 tool components in merged SBOM (trivy and sbomctl), got %d", len(tools))
	}

	// Check that trivy appears only once
	trivyCount := 0
	var trivyComp cyclonedx.Component
	for _, comp := range tools {
		if comp.Name == "trivy" {
			trivyCount++
			trivyComp = comp
		}
	}
	if trivyCount != 1 {
		t.Errorf("Expected trivy to appear once, but it appeared %d times", trivyCount)
	}

	// Verify that the trivy tool has publisher information
	if trivyComp.Publisher != "aquasecurity" {
		t.Errorf("Expected trivy tool to have publisher 'aquasecurity', but got '%s'", trivyComp.Publisher)
	}
}

func TestMergeSBOMsWithToolsComponents(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-tools-components")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with a tool in the components field
	sbom1 := cyclonedx.NewBOM()
	sbom1.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Type:      cyclonedx.ComponentTypeApplication,
					Name:      "trivy",
					Version:   "0.61.0",
					Publisher: "aquasecurity",
				},
			},
		},
	}
	sbom1.Components = &[]cyclonedx.Component{
		{
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	// Create second SBOM with a tool in the components field
	sbom2 := cyclonedx.NewBOM()
	sbom2.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Name:      "Tool B",
					Version:   "2.0.0",
					Publisher: "Vendor B",
					Type:      cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}
	sbom2.Components = &[]cyclonedx.Component{
		{
			Name:    "component-b",
			Version: "2.0.0",
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has tools metadata
	if mergedBom.Metadata == nil || mergedBom.Metadata.Tools == nil || mergedBom.Metadata.Tools.Components == nil {
		t.Fatal("Merged SBOM has no tools metadata")
	}

	// Verify the merged SBOM has all the expected tool components (including sbomctl)
	tools := *mergedBom.Metadata.Tools.Components
	if len(tools) != 3 {
		t.Fatalf("Expected 3 tool components in merged SBOM (trivy, Tool B, and sbomctl), got %d", len(tools))
	}

	// Check for expected tool components
	toolNames := make(map[string]bool)
	for _, comp := range tools {
		toolNames[comp.Name] = true
	}

	expectedTools := []string{"trivy", "Tool B", "sbomctl"}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Expected tool %s in merged SBOM, but it was not found", name)
		}
	}
}

func TestMergeSBOMsWithRealTestData(t *testing.T) {
	// Read the original SBOMs to debug
	sbom1, err := ReadSBOMFile("../../testdata/sbom1.json")
	if err != nil {
		t.Fatalf("Failed to read SBOM 1: %v", err)
	}

	sbom2, err := ReadSBOMFile("../../testdata/sbom2.json")
	if err != nil {
		t.Fatalf("Failed to read SBOM 2: %v", err)
	}

	// Debug: Print tools from original SBOMs
	if sbom1.Metadata != nil && sbom1.Metadata.Tools != nil {
		t.Logf("SBOM 1 Tools: %+v", sbom1.Metadata.Tools)
	} else {
		t.Log("SBOM 1 has no tools")
	}

	if sbom2.Metadata != nil && sbom2.Metadata.Tools != nil {
		t.Logf("SBOM 2 Tools: %+v", sbom2.Metadata.Tools)
	} else {
		t.Log("SBOM 2 has no tools")
	}

	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-real-data")
	err = os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Output path for the merged SBOM
	outputPath := filepath.Join(testDir, "merged.json")

	// Test merging the real test data SBOMs
	err = MergeSBOMs([]string{"../../testdata/sbom1.json", "../../testdata/sbom2.json"}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has tools metadata
	if mergedBom.Metadata == nil || mergedBom.Metadata.Tools == nil || mergedBom.Metadata.Tools.Components == nil {
		t.Fatal("Merged SBOM has no tools metadata")
	}

	// Verify the merged SBOM has all the expected tools
	tools := *mergedBom.Metadata.Tools.Components
	if len(tools) < 3 {
		t.Fatalf("Expected at least 3 tools in merged SBOM (SBOM Generator, Another SBOM Generator, and sbomctl), got %d", len(tools))
	}

	// Check for expected tools
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	expectedTools := []string{"SBOM Generator", "Another SBOM Generator", "sbomctl"}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Expected tool %s in merged SBOM, but it was not found", name)
		}
	}
}

func TestMergeSBOMsPreservesTools(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-tools")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with a tool
	sbom1 := cyclonedx.NewBOM()
	sbom1.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Name:      "Tool A",
					Version:   "1.0.0",
					Publisher: "Vendor A",
					Type:      cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}
	sbom1.Components = &[]cyclonedx.Component{
		{
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	// Create second SBOM with a different tool
	sbom2 := cyclonedx.NewBOM()
	sbom2.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Name:      "Tool B",
					Version:   "2.0.0",
					Publisher: "Vendor B",
					Type:      cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}
	sbom2.Components = &[]cyclonedx.Component{
		{
			Name:    "component-b",
			Version: "2.0.0",
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has tools metadata
	if mergedBom.Metadata == nil || mergedBom.Metadata.Tools == nil || mergedBom.Metadata.Tools.Components == nil {
		t.Fatal("Merged SBOM has no tools metadata")
	}

	// Verify the merged SBOM has all the expected tool components (including sbomctl)
	tools := *mergedBom.Metadata.Tools.Components
	if len(tools) != 3 {
		t.Fatalf("Expected 3 tool components in merged SBOM (Tool A, Tool B, and sbomctl), got %d", len(tools))
	}

	// Check for expected tool components
	toolNames := make(map[string]bool)
	for _, comp := range tools {
		toolNames[comp.Name] = true
	}

	expectedTools := []string{"Tool A", "Tool B", "sbomctl"}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Expected tool %s in merged SBOM, but it was not found", name)
		}
	}
}

func TestMergeSBOMsDeduplicatesTools(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-tools-dedup")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test SBOM files
	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	// Create first SBOM with a tool
	sbom1 := cyclonedx.NewBOM()
	sbom1.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Name:      "Common Tool",
					Version:   "1.0.0",
					Publisher: "Vendor X",
					Type:      cyclonedx.ComponentTypeApplication,
				},
				{
					Name:      "Tool A",
					Version:   "1.0.0",
					Publisher: "Vendor A",
					Type:      cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}
	sbom1.Components = &[]cyclonedx.Component{
		{
			Name:    "component-a",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}

	// Create second SBOM with the same tool and a different one
	sbom2 := cyclonedx.NewBOM()
	sbom2.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Name:      "Common Tool",
					Version:   "1.0.0",
					Publisher: "Vendor X",
					Type:      cyclonedx.ComponentTypeApplication,
				},
				{
					Name:      "Tool B",
					Version:   "2.0.0",
					Publisher: "Vendor B",
					Type:      cyclonedx.ComponentTypeApplication,
				},
			},
		},
	}
	sbom2.Components = &[]cyclonedx.Component{
		{
			Name:    "component-b",
			Version: "2.0.0",
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
	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	// Read the merged SBOM
	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Verify the merged SBOM has tools metadata
	if mergedBom.Metadata == nil || mergedBom.Metadata.Tools == nil || mergedBom.Metadata.Tools.Components == nil {
		t.Fatal("Merged SBOM has no tools metadata")
	}

	// Verify the merged SBOM has all the expected tool components (including sbomctl) with duplicates removed
	tools := *mergedBom.Metadata.Tools.Components
	if len(tools) != 4 {
		t.Fatalf("Expected 4 tool components in merged SBOM (Common Tool, Tool A, Tool B, and sbomctl), got %d", len(tools))
	}

	// Check for expected tool components
	toolNames := make(map[string]bool)
	for _, comp := range tools {
		toolNames[comp.Name] = true
	}

	expectedTools := []string{"Common Tool", "Tool A", "Tool B", "sbomctl"}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Expected tool %s in merged SBOM, but it was not found", name)
		}
	}

	// Verify that Common Tool appears only once
	commonToolCount := 0
	for _, comp := range tools {
		if comp.Name == "Common Tool" {
			commonToolCount++
		}
	}
	if commonToolCount != 1 {
		t.Errorf("Expected Common Tool to appear once, but it appeared %d times", commonToolCount)
	}
}

func TestMergeSBOMs_PrefixedRefs(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "sbomctl-test-prefixed-refs")
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	sbom1Path := filepath.Join(testDir, "sbom1.json")
	sbom2Path := filepath.Join(testDir, "sbom2.json")
	outputPath := filepath.Join(testDir, "merged.json")

	sn1 := "urn:uuid:serial-1"
	sn2 := "urn:uuid:serial-2"

	sbom1 := cyclonedx.NewBOM()
	sbom1.SerialNumber = sn1
	sbom1.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "pkg:npm/foo@1.0.0",
			Name:    "foo",
			Version: "1.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			BOMRef:  "pkg:npm/bar@2.0.0",
			Name:    "bar",
			Version: "2.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}
	sbom1.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref:          "pkg:npm/foo@1.0.0",
			Dependencies: &[]string{"pkg:npm/bar@2.0.0"},
		},
	}

	sbom2 := cyclonedx.NewBOM()
	sbom2.SerialNumber = sn2
	sbom2.Components = &[]cyclonedx.Component{
		{
			BOMRef:  "pkg:npm/bar@2.0.0",
			Name:    "bar",
			Version: "2.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
		{
			BOMRef:  "pkg:npm/baz@3.0.0",
			Name:    "baz",
			Version: "3.0.0",
			Type:    cyclonedx.ComponentTypeLibrary,
		},
	}
	sbom2.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref:          "pkg:npm/bar@2.0.0",
			Dependencies: &[]string{"pkg:npm/baz@3.0.0"},
		},
	}

	if err := WriteSBOMFile(sbom1, sbom1Path); err != nil {
		t.Fatalf("Failed to write test SBOM 1: %v", err)
	}
	if err := WriteSBOMFile(sbom2, sbom2Path); err != nil {
		t.Fatalf("Failed to write test SBOM 2: %v", err)
	}

	err = MergeSBOMs([]string{sbom1Path, sbom2Path}, outputPath, "", "")
	if err != nil {
		t.Fatalf("Failed to merge SBOMs: %v", err)
	}

	mergedBom, err := ReadSBOMFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read merged SBOM: %v", err)
	}

	// Check that all bom-refs and dependency refs are prefixed
	for _, c := range *mergedBom.Components {
		if c.BOMRef != "" && !(c.BOMRef == "merged-sbom" || c.BOMRef == mergedBom.Metadata.Component.BOMRef) {
			if !(len(c.BOMRef) > 10 && (c.BOMRef[:len(sn1)] == sn1 || c.BOMRef[:len(sn2)] == sn2)) {
				t.Errorf("Component BOMRef not prefixed: %s", c.BOMRef)
			}
		}
	}
	for _, d := range *mergedBom.Dependencies {
		if d.Ref != "" && d.Ref != mergedBom.Metadata.Component.BOMRef {
			if !(len(d.Ref) > 10 && (d.Ref[:len(sn1)] == sn1 || d.Ref[:len(sn2)] == sn2)) {
				t.Errorf("Dependency ref not prefixed: %s", d.Ref)
			}
		}
		if d.Dependencies != nil {
			for _, dep := range *d.Dependencies {
				if !(len(dep) > 10 && (dep[:len(sn1)] == sn1 || dep[:len(sn2)] == sn2)) {
					t.Errorf("dependsOn ref not prefixed: %s", dep)
				}
			}
		}
	}
}
