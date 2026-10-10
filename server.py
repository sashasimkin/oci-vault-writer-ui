#!/usr/bin/env python3
"""Small, memory-only Flask UI for updating allowlisted OCI Vault secrets."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, make_response, render_template, request

MAX_VALUE_BYTES = 24_000
ALIAS_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SECRET_ID_PATTERN = re.compile(r"^ocid1\.vaultsecret\.[A-Za-z0-9._-]+$")
WRITE_LOCK = threading.Lock()


def load_catalog(path: str) -> dict[str, dict[str, str]]:
    catalog = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or not catalog:
        raise ValueError("empty writer catalog")
    normalized: dict[str, dict[str, str]] = {}
    seen_ids: set[str] = set()
    for alias, item in catalog.items():
        if not isinstance(alias, str) or not ALIAS_PATTERN.fullmatch(alias):
            raise ValueError("invalid catalog alias")
        if not isinstance(item, dict):
            raise ValueError("invalid catalog item")
        secret_id = item.get("id")
        name = item.get("name")
        description = item.get("description", "")
        if not isinstance(secret_id, str) or not SECRET_ID_PATTERN.fullmatch(secret_id):
            raise ValueError("invalid catalog ID")
        if secret_id in seen_ids:
            raise ValueError("duplicate catalog ID")
        if not isinstance(name, str) or not name or len(name) > 256:
            raise ValueError("invalid catalog name")
        if not isinstance(description, str) or len(description) > 512:
            raise ValueError("invalid catalog description")
        normalized[alias] = {"id": secret_id, "name": name, "description": description}
        seen_ids.add(secret_id)
    return normalized


def update_secret(vault_client, secret: dict[str, str], value: str, alias: str) -> int | None:
    import oci

    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    version_name = datetime.now(timezone.utc).strftime("web-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8] + "-" + alias
    details = oci.vault.models.UpdateSecretDetails(
        secret_content=oci.vault.models.Base64SecretContentDetails(
            name=version_name, stage="CURRENT", content=encoded
        )
    )
    response = vault_client.update_secret(
        secret["id"], details, opc_retry_token=str(uuid.uuid4()),
        retry_strategy=oci.retry.NoneRetryStrategy(),
    )
    version = getattr(response.data, "current_version_number", None)
    return version if isinstance(version, int) else None


def build_vault_client(config_path: str, profile: str, expected_user: str):
    import oci

    config = oci.config.from_file(config_path, profile)
    if config.get("user") != expected_user:
        raise ValueError("unexpected OCI writer identity")
    if not all(config.get(key) for key in ("tenancy", "fingerprint", "key_file", "region")):
        raise ValueError("incomplete OCI signing configuration")
    if not Path(config["key_file"]).is_file():
        raise ValueError("OCI signing key is unavailable")
    return oci.vault.VaultsClient(config, retry_strategy=oci.retry.NoneRetryStrategy())


def create_app(catalog: dict[str, dict[str, str]], vault_client, public_origin: str) -> Flask:
    app = Flask(__name__, template_folder="web", static_folder="static")
    app.config.update(MAX_CONTENT_LENGTH=100_000, PUBLIC_ORIGIN=public_origin.rstrip("/"))
    # Neither Flask nor Werkzeug access/error logs may record request contents.
    app.logger.disabled = True
    logging.getLogger("werkzeug").disabled = True
    app.config["SECRET_KEY"] = None

    @app.after_request
    def secure_headers(response):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        return response

    @app.get("/")
    def index():
        return render_template("index.html", catalog=sorted(catalog.items()))

    @app.get("/healthz")
    def healthz():
        return "ok", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.post("/api/write")
    def write():
        origin = request.headers.get("Origin")
        host = request.headers.get("Host")
        if origin != app.config["PUBLIC_ORIGIN"] or host != urlsplit(app.config["PUBLIC_ORIGIN"]).netloc:
            abort(403)
        if request.mimetype != "application/x-www-form-urlencoded":
            abort(415)
        alias = request.form.get("alias", "")
        value = request.form.get("value", "")
        if alias not in catalog or not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            abort(400)
        try:
            with WRITE_LOCK:
                version = update_secret(vault_client, catalog[alias], value, alias)
            return render_template("status.html", ok=True, version=version), 200
        except Exception:
            # No exception or request details are logged or returned.
            # A 2xx fragment lets HTMX render the generic failure without
            # exposing any SDK response or submitted value.
            return render_template("status.html", ok=False, version=None), 200
        finally:
            value = None

    return app


def load_app() -> Flask:
    try:
        catalog = load_catalog(os.environ["WRITER_CATALOG_FILE"])
        expected_user = os.environ["OCI_EXPECTED_USER_OCID"]
        public_origin = os.environ["PUBLIC_ORIGIN"].rstrip("/")
        origin = urlsplit(public_origin)
        if (not expected_user.startswith("ocid1.user.") or origin.scheme != "https" or not origin.netloc
                or origin.path or origin.query or origin.fragment):
            raise ValueError("invalid writer settings")
        client = build_vault_client(os.environ.get("OCI_CONFIG_FILE", "/run/oci/config"),
                                    os.environ.get("OCI_PROFILE", "VAULT_SECRET_WRITER"), expected_user)
        return create_app(catalog, client, public_origin)
    except Exception:
        raise SystemExit("Vault writer configuration is invalid; refusing to start.") from None


app = load_app() if os.environ.get("WRITER_CATALOG_FILE") else Flask(__name__)
