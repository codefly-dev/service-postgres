# PostgreSQL workload attachment v1

`v1.schema.json` is the public, transport-neutral JSON envelope for a PostgreSQL
local identity proxy's pod attachment. `libs/go/workloadattachment` provides a
strict parser, validation and integrity sealing. The checked-in `example.json`
is synthetic and has a cross-language tested canonical digest.

The platform producer supplies a reviewed `binding`, exact namespace/service
account, pod security context, sidecars, volumes and application volume mounts.
Consumers validate the schema and digest, then compare the binding and workload
identity with their separately reviewed desired configuration before copying the
explicit fields. No consumer may extract production inputs from qualification
Job positions, SQL scripts, argv or arbitrary init-container order.

The seal is `sha256:` of UTF-8 JSON with sorted object keys, compact separators,
no ASCII or HTML escaping, and only the top-level `digest` omitted. Arrays retain
order. It detects changed content; it is not a signature, grant or proof of a live
connection. Both schema and the specific attachment digest need owner review.
Inputs must contain one UTF-8 JSON document with unique object keys and the exact
published field names and types. Case aliases, null in place of an optional
boolean, and lossy Unicode replacements are rejected before admission; they
cannot borrow the seal of a normalized document. Whitespace and valid JSON string
escapes do not change the decoded content or its seal.

Version 1 permits only passwordless local identity proxy connections, pinned
native sidecars, memory-backed private socket volumes, read-only application
mounts, and explicit nonroot security. It has no arbitrary Kubernetes resource
payload, host mount, environment credentials, service image, migration, role or
IAM operation. Names, database usernames and transport fragments come from the
owning primitive/platform binding. Group names and grant algorithms are never
reconstructed here. Cloud-specific proxy arguments and live delegation validation
remain with the existing platform producer; SQL access policy remains with the
PostgreSQL control-plane and schema-plan engines.

A consumer checks all referenced volumes and confirms its configured socket lives
under a read-only application mount. Changed identity, socket or security fields
must fail admission against the approved consumer inputs, even if somebody
reseals the modified attachment. A second target changes only binding/namespace/
service-account/transport data; it does not add environment conditionals.

This public interface is independent of schema-plan v1/v2 and delegated read-only
roles. It neither upgrades a schema-plan engine nor changes historical migrations.
Run `go test ./libs/go/workloadattachment` for malformed contracts, strict fields,
security/reference denials, canonical seal consistency and second-target coverage.
Cloud connectivity, IAM grants and database privileges still require their normal
owner qualification; passing attachment validation makes none of those claims.
