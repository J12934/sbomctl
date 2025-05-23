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

```sh
$ sbomctl inspect scbctl.sbom.json
File:           scbctl.sbom.json
SBOM Format:    CycloneDX
Spec Version:   1.6
Serial Number:  urn:uuid:861f6737-d669-4abf-9503-550e7561018c
Version:        1

Metadata:
  Timestamp:  2025-05-16T19:09:18+00:00
  Tools:
    - trivy (v0.62.1)

Components:
  Total Components:  7
  Component Types:
    - application:  1
    - library:      6

  Top Components (max 10):
    Name                                  Version  Type         PURL
    github.com/CycloneDX/cyclonedx-go     v0.9.2   library      pkg:golang/github.com/cyclonedx/cyclonedx-go@v0.9.2
    github.com/google/uuid                v1.6.0   library      pkg:golang/github.com/google/uuid@v1.6.0
    github.com/inconshreveable/mousetrap  v1.1.0   library      pkg:golang/github.com/inconshreveable/mousetrap@v1.1.0
    github.com/j12934/sbomctl                      library      pkg:golang/github.com/j12934/sbomctl
    github.com/spf13/cobra                v1.9.1   library      pkg:golang/github.com/spf13/cobra@v1.9.1
    github.com/spf13/pflag                v1.0.6   library      pkg:golang/github.com/spf13/pflag@v1.0.6
    go.mod                                         application

Dependencies:
  Total Dependencies:           8
  Dependencies with dependsOn:  4
  Max dependsOn count:          3
```
