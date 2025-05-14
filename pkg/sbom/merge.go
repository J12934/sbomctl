package sbom

import (
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/CycloneDX/cyclonedx-go"
)

// MergeSBOMs merges multiple SBOM files into a single SBOM file
func MergeSBOMs(inputFiles []string, outputFile string) error {
	// Create a new BOM to hold the merged result
	mergedBom := cyclonedx.NewBOM()
	mergedBom.SerialNumber = "urn:uuid:" + uuid.New().String()
	mergedBom.Version = 1

	// Set metadata
	mergedBom.Metadata = &cyclonedx.Metadata{
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					BOMRef:    "sbomctl",
					Name:      "sbomctl",
					Version:   "0.1.0",
					Type:      cyclonedx.ComponentTypeApplication,
					Publisher: "j12934",
				},
			},
		},
	}

	// Initialize components slice
	mergedBom.Components = &[]cyclonedx.Component{}

	// Process each input file
	for _, file := range inputFiles {
		// Read the SBOM file
		bom, err := ReadSBOMFile(file)
		if err != nil {
			return fmt.Errorf("failed to read SBOM file %s: %w", file, err)
		}

		// Merge components
		if bom.Components != nil {
			if mergedBom.Components == nil {
				mergedBom.Components = &[]cyclonedx.Component{}
			}
			*mergedBom.Components = append(*mergedBom.Components, *bom.Components...)
		}

		// Merge dependencies if present
		if bom.Dependencies != nil {
			if mergedBom.Dependencies == nil {
				mergedBom.Dependencies = &[]cyclonedx.Dependency{}
			}
			*mergedBom.Dependencies = append(*mergedBom.Dependencies, *bom.Dependencies...)
		}
	}

	// Remove duplicate components
	mergedBom.Components = deduplicateComponents(mergedBom.Components)

	// Remove duplicate dependencies
	mergedBom.Dependencies = deduplicateDependencies(mergedBom.Dependencies)

	// Write the merged SBOM to the output file
	return WriteSBOMFile(mergedBom, outputFile)
}

// ReadSBOMFile reads a CycloneDX SBOM file and returns the BOM object
// This is an exported version of readSBOMFile for use by other packages
func ReadSBOMFile(filename string) (*cyclonedx.BOM, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Create a new BOM decoder
	decoder := cyclonedx.NewBOMDecoder(file, cyclonedx.BOMFileFormatJSON)

	// Decode the BOM
	bom := &cyclonedx.BOM{}
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("failed to decode BOM: %w", err)
	}

	return bom, nil
}

// WriteSBOMFile writes a CycloneDX BOM to a file
// This is an exported version of writeSBOMFile for use by other packages
func WriteSBOMFile(bom *cyclonedx.BOM, filename string) error {
	// Create the output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Create a new BOM encoder
	encoder := cyclonedx.NewBOMEncoder(file, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	// Encode the BOM
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("failed to encode BOM: %w", err)
	}

	return nil
}

// deduplicateComponents removes duplicate components from the BOM
func deduplicateComponents(components *[]cyclonedx.Component) *[]cyclonedx.Component {
	if components == nil {
		return nil
	}

	// Use a map to track unique components by their PURL
	seen := make(map[string]bool)
	var unique []cyclonedx.Component

	for _, component := range *components {
		// Use PURL as the unique identifier if available, otherwise use name+version
		key := component.PackageURL
		if key == "" {
			key = component.Name
			if component.Version != "" {
				key += "@" + component.Version
			}
		}

		if !seen[key] {
			seen[key] = true
			unique = append(unique, component)
		}
	}

	return &unique
}

// deduplicateDependencies removes duplicate dependencies from the BOM
// and merges their dependsOn lists
func deduplicateDependencies(dependencies *[]cyclonedx.Dependency) *[]cyclonedx.Dependency {
	if dependencies == nil {
		return nil
	}

	// Map to store unique dependencies by ref
	depMap := make(map[string]*cyclonedx.Dependency)

	// Process each dependency
	for _, dep := range *dependencies {
		// If we haven't seen this ref before, add it to the map
		if existing, exists := depMap[dep.Ref]; !exists {
			// Create a copy of the dependency
			newDep := dep
			depMap[dep.Ref] = &newDep
		} else {
			// Merge dependsOn lists if both exist
			if dep.Dependencies != nil && len(*dep.Dependencies) > 0 {
				if existing.Dependencies == nil {
					existing.Dependencies = &[]string{}
				}

				// Add each dependency if it doesn't already exist
				for _, d := range *dep.Dependencies {
					found := false
					for _, existingDep := range *existing.Dependencies {
						if existingDep == d {
							found = true
							break
						}
					}

					if !found {
						*existing.Dependencies = append(*existing.Dependencies, d)
					}
				}
			}
		}
	}

	// Convert map back to slice
	var result []cyclonedx.Dependency
	for _, dep := range depMap {
		result = append(result, *dep)
	}

	return &result
}
