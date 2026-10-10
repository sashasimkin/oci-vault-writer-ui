# OCI Vault Writer UI

A small, stateless web application for creating new versions of explicitly
allowlisted OCI Vault secrets. An operator chooses a catalog alias, submits a
value, and the application calls OCI Vault's UpdateSecret API. The application
does not read or list secret payloads.

## What it does

- Provides a browser form for selecting an allowed secret and submitting a new
  value.
- Maps catalog aliases to preconfigured Vault secret OCIDs; clients cannot
  choose arbitrary OCIDs.
- Sends values directly to OCI Vault over TLS without persistent storage.
- Returns the resulting version number, or a generic message when the result
  cannot be confirmed.
- Serves its UI and locally vendored HTMX assets from the same application.

## Security model

The application is intended to run behind an HTTPS ingress that enforces
operator authentication and a trusted-client allowlist. The web application
itself is not an authentication boundary. Use a dedicated OCI API signing
identity with only the required secret-version update permissions, and mount
its configuration and key read-only.

Request and error details are not logged or returned to the browser. The
browser does not persist submitted values. The catalog should contain only
allowed secret identifiers and display metadata, never payloads. Keep actual
OCI credentials and catalog contents out of source control, image layers,
workflow logs, and CI artifacts.

If a write result is ambiguous, inspect only non-payload version metadata before
retrying; this interface cannot read a value back.

## Configuration

| Environment variable | Purpose |
| --- | --- |
| WRITER_CATALOG_FILE | Path to a JSON map of allowed aliases to id, name, and description |
| OCI_EXPECTED_USER_OCID | Expected OCI user OCID; must match the mounted config |
| PUBLIC_ORIGIN | Canonical HTTPS origin used for Host/Origin validation |
| OCI_CONFIG_FILE | OCI config path; defaults to /run/oci/config |
| OCI_PROFILE | OCI profile; defaults to VAULT_SECRET_WRITER |

Mount the catalog and OCI config/key read-only. The signing key must remain
outside the image.

## Helm chart

The reusable deployment chart is maintained alongside the application at
[`charts/vault-writer`](charts/vault-writer). It is disabled by default and
requires Traefik's `IngressRoute` and `Middleware` CRDs, plus pre-created
runtime catalog, OCI signing-config, and authentication Secrets. Set
cluster-specific ingress, network, Secret, and resource values in the consuming
GitOps repository rather than in this public chart.

## Container image

Pull requests validate the application and build an image without publishing.
Authorized branch and version-tag pushes publish multi-architecture images to
GHCR. Semantic prerelease tags such as `0.1.0-rc.2` are intended for pre-merge
deployment checks; stable version tags are published after verification.

Example prerelease pull command:

    docker pull ghcr.io/sashasimkin/oci-vault-writer-ui:0.1.0-rc.2

## Local development

Dependencies are declared in `pyproject.toml` and locked in `uv.lock`.

    uv sync --locked
    PYTHONPATH=. uv run --locked --no-sync python -m unittest discover -s tests -v
    docker build --tag oci-vault-writer-ui:local .
