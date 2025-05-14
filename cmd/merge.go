package cmd

import (
	"fmt"

	"github.com/j12934/sbomctl/pkg/sbom"
	"github.com/spf13/cobra"
)

var outputFile string

// mergeCmd represents the merge command
var mergeCmd = &cobra.Command{
	Use:   "merge [sbom files...]",
	Short: "Merge multiple SBOM files into one",
	Long: `Merge multiple CycloneDX SBOM files into a single SBOM file.
	
Example:
  sbomctl merge sbom1.sbom.json sbom2.sbom.json -o merged.sbom.json`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get the input files from args
		inputFiles := args

		// Merge the SBOM files
		err := sbom.MergeSBOMs(inputFiles, outputFile)
		if err != nil {
			return fmt.Errorf("failed to merge SBOM files: %w", err)
		}

		fmt.Printf("Successfully merged %d SBOM files into %s\n", len(inputFiles), outputFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mergeCmd)

	// Add flags for the merge command
	mergeCmd.Flags().StringVarP(&outputFile, "output", "o", "merged.sbom.json", "Output file for the merged SBOM")
}
