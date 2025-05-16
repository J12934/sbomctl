# sbomctl

sbomctl is a CLI tool for managing Software Bill of Materials (SBOM) in the [CycloneDX](https://cyclonedx.org/) format.

It provides commands to inspect and merge SBOM files.

At the moment this is mostly experimental, to deal with issues with the official [cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli).
The cyclone-dx which generally works pretty well, but has issues merging sboms when they have (some) overlapping dependencies. The merged sboms in the cases are invalid having multiple non-unique bomRefs.

## Installation

Build from source:

```sh
go install github.com/j12934/sbomctl@latest
```

## Usage

Run `sbomctl --help` to see all available commands and options.

### Merge Command

Merge multiple CycloneDX SBOM files into a single SBOM, deduplicating components, dependencies, and tools.

**Basic usage:**

```sh
sbomctl merge sbom1.json sbom2.json -o merged.json
```

- `sbom1.json sbom2.json` — input SBOM files to merge (at least two required)
- `-o merged.json` — output file for the merged SBOM (default: `merged.sbom.json`)

**Customizing the merged component:**

You can set a custom name and version for the merged SBOM's root component:

```sh
sbomctl merge sbom1.json sbom2.json \
  --merged-component-name my-app-sbom \
  --merged-component-version 1.2.3 \
  -o my-merged.json
```

### Inspect Command

Quickly display summary information about a CycloneDX SBOM file, including component counts, types, tools, and dependencies.

**Example:**

```sh
sbomctl inspect sbom.json
```

This prints a summary with details such as:

- SBOM format, version, and serial number
- Metadata (timestamp, tools)
- Number and types of components
- Top components
- Dependency statistics
