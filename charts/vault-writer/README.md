# OCI Vault Writer deployment chart

This Helm chart deploys the OCI Vault Writer UI from this repository.
It is disabled by default.

## Configuration

Provide deployment-specific values for the image and tag, public origin, runtime
catalog Secret, OCI signing credential Secret, one-user BasicAuth Secret, source
IPv4 CIDR, ingress hostname, and TLS Secret. Keep these bindings in the consuming
GitOps configuration rather than chart defaults.

`debugDiagnostics` defaults to `false`. When enabled, write logs include a
SHA-256 digest, request shape, OCI service message, and response headers. The
submitted value and its base64, URL-encoded, and JSON-escaped forms are masked
as `****` throughout diagnostic fields and header names/values. Authorization,
proxy-authorization, cookie, set-cookie, and WWW-Authenticate response headers
are always masked. Request/response bodies and tracebacks are never logged; do
not enable OCI SDK HTTP wire/debug logging. The writer logger has its own
INFO-level stderr handler so Gunicorn does not suppress these diagnostics.

Image-pull credentials are optional and should be configured only when the
selected container registry requires authentication. The public GHCR image does
not need an image-pull Secret.

## Security requirements

- Create the runtime catalog, OCI signing-config, and authentication Secrets out
  of band before enabling the chart.
- Restrict the route to a trusted network and use a single operator-controlled
  IPv4 `/32` allowlist.
- The OCI signing identity should have only the required secret-version update
  permissions; mount its config and key read-only.
- The workload does not need a Kubernetes API token or RBAC, and the catalog
  must not contain secret payloads.
- Gunicorn error logs are sent to stderr for startup diagnosis. Application
  diagnostics intentionally omit exception details and request contents.
