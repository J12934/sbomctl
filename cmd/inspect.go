package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/j12934/sbomctl/pkg/sbom"
	"github.com/spf13/cobra"
)

// formatSBOMInfo formats the SBOM information and writes it to the provided writer
// This function is exported for testing purposes
func formatSBOMInfo(w io.Writer, bom *cyclonedx.BOM, inputFile string) {
	// Print basic information
	fmt.Fprintf(w, "File:\t%s\n", inputFile)
	fmt.Fprintf(w, "SBOM Format:\t%s\n", bom.BOMFormat)
	fmt.Fprintf(w, "Spec Version:\t%s\n", bom.SpecVersion)
	fmt.Fprintf(w, "Serial Number:\t%s\n", bom.SerialNumber)
	fmt.Fprintf(w, "Version:\t%d\n", bom.Version)

	// Print metadata if available
	if bom.Metadata != nil {
		fmt.Fprintln(w, "\nMetadata:")
		if bom.Metadata.Timestamp != "" {
			fmt.Fprintf(w, "  Timestamp:\t%s\n", bom.Metadata.Timestamp)
		}

		// Print tools information if available
		if bom.Metadata.Tools != nil {
			fmt.Fprintln(w, "  Tools:")

			// Handle deprecated Tools field (for backward compatibility)
			if bom.Metadata.Tools.Tools != nil {
				for _, tool := range *bom.Metadata.Tools.Tools {
					fmt.Fprintf(w, "    - %s", tool.Name)
					if tool.Version != "" {
						fmt.Fprintf(w, " (v%s)", tool.Version)
					}
					if tool.Vendor != "" {
						fmt.Fprintf(w, " by %s", tool.Vendor)
					}
					fmt.Fprintln(w)
				}
			}

			// Handle new Components field
			if bom.Metadata.Tools.Components != nil {
				for _, component := range *bom.Metadata.Tools.Components {
					fmt.Fprintf(w, "    - %s", component.Name)
					if component.Version != "" {
						fmt.Fprintf(w, " (v%s)", component.Version)
					}
					if component.Publisher != "" {
						fmt.Fprintf(w, " by %s", component.Publisher)
					}
					fmt.Fprintln(w)
				}
			}
		}
	}

	// Print component information
	fmt.Fprintln(w, "\nComponents:")
	if bom.Components != nil && len(*bom.Components) > 0 {
		fmt.Fprintf(w, "  Total Components:\t%d\n", len(*bom.Components))

		// Count component types
		typeCount := make(map[string]int)
		for _, comp := range *bom.Components {
			typeCount[string(comp.Type)]++
		}

		// Print component types
		fmt.Fprintln(w, "  Component Types:")
		types := make([]string, 0, len(typeCount))
		for t := range typeCount {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			fmt.Fprintf(w, "    - %s:\t%d\n", t, typeCount[t])
		}

		// Print top components (limited to 10 for readability)
		fmt.Fprintln(w, "\n  Top Components (max 10):")
		fmt.Fprintln(w, "    Name\tVersion\tType\tPURL")

		// Sort components by name for consistent output
		components := *bom.Components
		sort.Slice(components, func(i, j int) bool {
			return strings.ToLower(components[i].Name) < strings.ToLower(components[j].Name)
		})

		// Print up to 10 components
		limit := 10
		if len(components) < limit {
			limit = len(components)
		}

		for i := 0; i < limit; i++ {
			comp := components[i]
			fmt.Fprintf(w, "    %s\t%s\t%s\t%s\n",
				comp.Name,
				comp.Version,
				string(comp.Type),
				comp.PackageURL)
		}

		// Indicate if there are more components
		if len(components) > 10 {
			fmt.Fprintf(w, "    ... and %d more components\n", len(components)-10)
		}
	} else {
		fmt.Fprintln(w, "  No components found")
	}

	// Print dependency information
	fmt.Fprintln(w, "\nDependencies:")
	if bom.Dependencies != nil && len(*bom.Dependencies) > 0 {
		fmt.Fprintf(w, "  Total Dependencies:\t%d\n", len(*bom.Dependencies))

		// Count dependencies with dependsOn
		withDependsOn := 0
		maxDependsOn := 0
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies != nil && len(*dep.Dependencies) > 0 {
				withDependsOn++
				if len(*dep.Dependencies) > maxDependsOn {
					maxDependsOn = len(*dep.Dependencies)
				}
			}
		}

		fmt.Fprintf(w, "  Dependencies with dependsOn:\t%d\n", withDependsOn)
		fmt.Fprintf(w, "  Max dependsOn count:\t%d\n", maxDependsOn)
	} else {
		fmt.Fprintln(w, "  No dependencies found")
	}
}

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect [sbom file]",
	Short: "Inspect a SBOM file and show information about it",
	Long: `Inspect a CycloneDX SBOM file and display useful information about it,
such as the number of components, types of components, and other metadata.
	
Example:
  sbomctl inspect sbom.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get the input file from args
		inputFile := args[0]

		// Read the SBOM file
		bom, err := sbom.ReadSBOMFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read SBOM file: %w", err)
		}

		// Create a tabwriter for formatted output
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		defer w.Flush()

		// Format and print the SBOM information
		formatSBOMInfo(w, bom, inputFile)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
