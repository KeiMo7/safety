# CycloneDX 1.5 output

Safety can write a CycloneDX 1.5 JSON BOM for downstream artifact repositories.
The feature is opt-in and does not change existing output formats or exit-code
semantics.

## Usage

Write the BOM to stdout:

```console
safety check --output cyclonedx > safety-report.cdx.json
```

The `--cyclonedx` flag is an alias for `--output cyclonedx`.
`cyclonedx-json` and `cyclonedx@1.5` are accepted as `--output` aliases for
callers that encode the format name.

Write the BOM atomically to a file:

```console
safety check --save-cyclonedx artifacts/safety-report.cdx.json
```

If the path is a directory, Safety uses
`safety-report-cyclonedx.json`. `--save-cyclonedx` can be combined with any
other output format, in which case the existing output remains unchanged and
the BOM is written in addition to it.

## Inventory behavior

- Every inventory component includes `type`, `name`, `version`, and `purl`.
- Components are deduplicated by `(name, version, purl)`, so multiple versions
  of the same package remain separate components.
- Package names retain their original casing and namespace. PURL path segments
  are percent-encoded, including non-ASCII package names.
- Each CVE is emitted as a separate vulnerability and references its affected
  component. `safety:declaration-file` records the declaration source.
- Component occurrences are written under CycloneDX `evidence.occurrences`.
- The root dependency references direct components. When Safety can identify a
  single direct chain, transitive components are children of that direct
  component; otherwise transitive components are grouped under the
  `urn:safety:scope:transitive` component.

Missing names, versions, or sources are retained as `unknown`; they are not
dropped. Components expose `safety:missing-metadata`, and BOM metadata exposes
these counters:

- `safety:degraded-components`
- `safety:missing-version-components`
- `safety:missing-source-components`
- `safety:missing-name-components`

Output is deterministic: components, dependencies, vulnerabilities, sources,
and properties have stable ordering, no timestamps or random identifiers are
written, and two runs over equivalent input are byte-comparable.

## Failure handling

The BOM is written component-by-component to the destination stream. File
output uses a same-directory temporary file and atomic replacement, so a failed
run does not publish a partial file. A failed stdout write can leave a partial
stream, which is observable through the non-zero exit and the error log.

Schema-invalid component data raises a CycloneDX output error that identifies
the component by index and field. Logs include only lifecycle status, counts,
component index, and field name. They do not include component values, absolute
paths, credentials, or user data.

Existing `--exit-code` behavior is preserved: 64 is returned when vulnerabilities
are found, and 0 when they are not. The new output path uses the same behavior.

## Concurrency

Each formatter invocation owns its component map, streams, and temporary file;
there is no shared mutable formatter state. Concurrent writes to different
paths are independent. Concurrent writes to the same path are atomic but
last-writer-wins, so callers that need a guaranteed stable result should
serialize writes to that path or use unique per-run paths.

Verification can run two concurrent `--save-cyclonedx` invocations against
distinct paths and compare both outputs byte-for-byte. A same-path test should
assert that the final file is a complete, schema-valid BOM from one of the
writers rather than a concatenation or partial document.

## Migration

No configuration keys were added. The default remains the existing
human-readable output, so no migration is required for current callers.

Before:

```console
safety check --json > safety-report.json
```

After:

```console
safety check --output cyclonedx --save-cyclonedx safety-report.cdx.json
```

The BOM validates against the official CycloneDX 1.5 schema:
`http://cyclonedx.org/schema/bom-1.5.schema.json`.
