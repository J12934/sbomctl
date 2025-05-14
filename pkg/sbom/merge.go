package sbom

import (
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/CycloneDX/cyclonedx-go"
)

// MergeSBOMs merges multiple SBOM files into a single SBOM file
func MergeSBOMs(inputFiles []string, outputFile string, componentName string, componentVersion string) error {
	// Create a new BOM to hold the merged result
	mergedBom := cyclonedx.NewBOM()
	mergedBom.SerialNumber = "urn:uuid:" + uuid.New().String()
	mergedBom.Version = 1

	// Use provided component name or default
	if componentName == "" {
		componentName = "merged-sbom"
	}

	// Generate a unique BOMRef for the merged SBOM
	mergedBomRef := componentName + "-" + uuid.New().String()

	// Create the component for the merged SBOM
	mergedComponent := cyclonedx.Component{
		BOMRef: mergedBomRef,
		Name:   componentName,
		Type:   cyclonedx.ComponentTypeApplication,
	}

	// Add version if provided
	if componentVersion != "" {
		mergedComponent.Version = componentVersion
	}

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
		Component: &mergedComponent,
	}

	// Initialize components slice
	mergedBom.Components = &[]cyclonedx.Component{}

	// Track components with metadata.component for dependencies
	var metadataComponents []cyclonedx.Component

	// Process each input file
	for _, file := range inputFiles {
		// Read the SBOM file
		bom, err := ReadSBOMFile(file)
		if err != nil {
			return fmt.Errorf("failed to read SBOM file %s: %w", file, err)
		}

		// Check if the SBOM has a metadata.component
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			// Add the metadata component to our tracking list
			metadataComponents = append(metadataComponents, *bom.Metadata.Component)

			// Add the metadata component to the components list if it's not already there
			if mergedBom.Components == nil {
				mergedBom.Components = &[]cyclonedx.Component{}
			}
			*mergedBom.Components = append(*mergedBom.Components, *bom.Metadata.Component)
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

	// Create dependencies for metadata components
	if len(metadataComponents) > 0 {
		// Ensure we have a dependencies section
		if mergedBom.Dependencies == nil {
			mergedBom.Dependencies = &[]cyclonedx.Dependency{}
		}

		// Create a dependency from the merged SBOM to each metadata component
		mergedBomDependency := cyclonedx.Dependency{
			Ref:          mergedBomRef,
			Dependencies: &[]string{},
		}

		// Add each metadata component as a dependency
		for _, comp := range metadataComponents {
			*mergedBomDependency.Dependencies = append(*mergedBomDependency.Dependencies, comp.BOMRef)
		}

		// Add the merged SBOM dependency to the dependencies list
		*mergedBom.Dependencies = append(*mergedBom.Dependencies, mergedBomDependency)
	}

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
