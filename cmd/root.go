package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sbomctl",
	Short: "A tool for managing Software Bill of Materials (SBOM)",
	Long: `sbomctl is a CLI tool for managing Software Bill of Materials (SBOM).
It provides various commands for working with SBOM files in CycloneDX format.`,
	// Print help if no subcommand is specified
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// No config file or persistent flags needed
}
