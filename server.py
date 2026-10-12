#!/usr/bin/env python3
"""Small, memory-only Flask UI for updating allowlisted OCI Vault secrets."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import re
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit

from flask import Flask, abort, make_response, render_template, request

MAX_VALUE_BYTES = 24_000
ALIAS_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SECRET_ID_PATTERN = re.compile(r"^ocid1\.vaultsecret\.[A-Za-z0-9._-]+$")
WRITE_LOCK = threading.Lock()
STARTUP_LOGGER = logging.getLogger("vault_writer")
WRITE_LOGGER = logging.getLogger("vault_writer.write")
WRITE_LOGGER.setLevel(logging.INFO)
WRITE_LOGGER.addHandler(logging.StreamHandler())
WRITE_LOGGER.propagate = False
SAFE_ERROR_CODE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
SAFE_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
SAFE_ERROR_FIELDS = ("secretContent", "contentType", "content", "name", "stage")
SAFE_ERROR_HINTS = ("base64", "invalid", "json", "parse", "required", "unsupported")
SENSITIVE_RESPONSE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate"
}


def log_startup(phase: str, outcome: str, error_type: str | None = None) -> None:
    if outcome == "failed":
        STARTUP_LOGGER.error(
            "writer_startup outcome=failed phase=%s error_type=%s",
            phase,
            error_type or "UnknownError",
        )
    elif os.environ.get("WRITER_DEBUG_DIAGNOSTICS", "").lower() == "true":
        STARTUP_LOGGER.info("writer_startup phase=%s outcome=%s", phase, outcome)


def redact_secret(text: str, value: str) -> str:
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    encoded_urlsafe = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
    variants = {
        value,
        encoded,
        encoded_urlsafe,
        quote(value, safe=""),
        quote_plus(value),
        html.escape(value, quote=True),
        repr(value)[1:-1],
        json.dumps(value, ensure_ascii=True)[1:-1],
        quote(encoded, safe=""),
        quote_plus(encoded),
        quote(encoded_urlsafe, safe=""),
        quote_plus(encoded_urlsafe),
    }
    for variant in sorted((item for item in variants if item), key=len, reverse=True):
        text = text.replace(variant, "****")
    return text


def safe_response_headers(headers, value: str) -> str:
    if not isinstance(headers, Mapping):
        return "{}"
    sanitized = {}
    for name, header_value in headers.items():
        safe_name = redact_secret(str(name), value)
        if str(name).lower() in SENSITIVE_RESPONSE_HEADERS:
            sanitized[safe_name] = "****"
        else:
            sanitized[safe_name] = redact_secret(str(header_value), value)
    return json.dumps(sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def log_write_failure(operation_id: str, alias: str, error: Exception, value: str) -> None:
    if os.environ.get("WRITER_DEBUG_DIAGNOSTICS", "").lower() != "true":
        return

    error_type = type(error).__name__
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", error_type):
        error_type = "UnknownError"
    error_code = getattr(error, "code", None)
    if not isinstance(error_code, str) or not SAFE_ERROR_CODE_PATTERN.fullmatch(error_code):
        error_code = "unknown"
    status = getattr(error, "status", None)
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        status = "unknown"
    request_id = getattr(error, "request_id", None)
    if not isinstance(request_id, str) or not SAFE_REQUEST_ID_PATTERN.fullmatch(request_id):
        request_id = "unknown"
    message = getattr(error, "message", None)
    if not isinstance(message, str):
        message = str(error)
    message = redact_secret(message, value)[:2048]
    if message:
        error_fields = [
            field for field in SAFE_ERROR_FIELDS
            if re.search(rf"(?<![A-Za-z0-9_]){field}(?![A-Za-z0-9_])", message, re.IGNORECASE)
        ]
        error_hints = [
            hint for hint in SAFE_ERROR_HINTS
            if re.search(rf"\b{hint}\b", message, re.IGNORECASE)
        ]
    else:
        error_fields = []
        error_hints = []

    headers = safe_response_headers(getattr(error, "headers", {}), value)

    context = (
        f"operation_id={operation_id} alias={alias} error_type={error_type} "
        f"error_code={error_code} http_status={status} oci_request_id={request_id} "
        f"error_fields={','.join(error_fields) or 'unknown'} "
        f"error_hints={','.join(error_hints) or 'unknown'} "
        f"service_message={json.dumps(message, ensure_ascii=True)} response_headers={headers}"
    )
    safe_context = redact_secret(context, value)
    secret_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    WRITE_LOGGER.warning("writer_write outcome=unconfirmed %s secret_sha256=%s", safe_context, secret_hash)


def log_write_request(operation_id: str, alias: str, value: str, encoded: str) -> None:
    if os.environ.get("WRITER_DEBUG_DIAGNOSTICS", "").lower() != "true":
        return

    size = len(value.encode("utf-8"))
    if size <= 256:
        size_bucket = "0_256"
    elif size <= 4096:
        size_bucket = "257_4096"
    else:
        size_bucket = "4097_plus"
    try:
        base64.b64decode(encoded, validate=True)
        base64_valid = "true"
    except (ValueError, TypeError):
        base64_valid = "false"

    context = (
        f"operation_id={operation_id} alias={alias} payload_size={size_bucket} "
        f"base64_valid={base64_valid} content_type=BASE64 stage=CURRENT "
        "request_fields=secretContent,contentType,name,stage,content"
    )
    safe_context = redact_secret(context, value)
    secret_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    WRITE_LOGGER.info("writer_write_request %s secret_sha256=%s", safe_context, secret_hash)


def log_write_success(
    operation_id: str, alias: str, response, version: int | None, value: str
) -> None:
    if os.environ.get("WRITER_DEBUG_DIAGNOSTICS", "").lower() != "true":
        return

    status = getattr(response, "status", None)
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        status = "unknown"
    outcome = "confirmed" if isinstance(version, int) and not isinstance(version, bool) else "response_unconfirmed"
    version_number = version if isinstance(version, int) and not isinstance(version, bool) else "unknown"
    context = (
        f"outcome={outcome} operation_id={operation_id} alias={alias} "
        f"http_status={status} current_version_number={version_number}"
    )
    safe_context = redact_secret(context, value)
    secret_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    WRITE_LOGGER.info("writer_write %s secret_sha256=%s", safe_context, secret_hash)


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


def update_secret(
    vault_client, secret: dict[str, str], value: str, alias: str, operation_id: str
) -> int | None:
    import oci

    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    version_name = datetime.now(timezone.utc).strftime("web-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8] + "-" + alias
    details = oci.vault.models.UpdateSecretDetails(
        secret_content=oci.vault.models.Base64SecretContentDetails(
            content_type="BASE64", name=version_name, stage="CURRENT", content=encoded
        ),
        enable_auto_generation=False,
    )
    log_write_request(operation_id, alias, value, encoded)
    response = vault_client.update_secret(
        secret["id"], details, opc_request_id=operation_id,
        retry_strategy=oci.retry.NoneRetryStrategy(),
    )
    version = getattr(response.data, "current_version_number", None)
    version = version if isinstance(version, int) and not isinstance(version, bool) else None
    log_write_success(operation_id, alias, response, version, value)
    return version


def build_vault_client(config_path: str, profile: str, expected_user: str):
    import oci

    log_startup("oci_config", "loading")
    config = oci.config.from_file(config_path, profile)
    log_startup("oci_config", "loaded")
    if config.get("user") != expected_user:
        raise ValueError("unexpected OCI writer identity")
    log_startup("oci_identity", "validated")
    if not all(config.get(key) for key in ("tenancy", "fingerprint", "key_file", "region")):
        raise ValueError("incomplete OCI signing configuration")
    log_startup("oci_signing_config", "validated")
    if not Path(config["key_file"]).is_file():
        raise ValueError("OCI signing key is unavailable")
    log_startup("oci_signing_key", "available")
    client = oci.vault.VaultsClient(config, retry_strategy=oci.retry.NoneRetryStrategy())
    log_startup("oci_client", "ready")
    return client


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
        operation_id = uuid.uuid4().hex
        try:
            with WRITE_LOCK:
                version = update_secret(vault_client, catalog[alias], value, alias, operation_id)
            return render_template("status.html", ok=True, version=version), 200
        except Exception as error:
            # Keep the HTMX response generic and redact the submitted value from diagnostics.
            log_write_failure(operation_id, alias, error, value)
            return render_template(
                "status.html", ok=False, version=None, operation_id=operation_id
            ), 200
        finally:
            value = None

    return app


def load_app() -> Flask:
    phase = "catalog"
    try:
        log_startup(phase, "loading")
        catalog = load_catalog(os.environ["WRITER_CATALOG_FILE"])
        log_startup(phase, "ready")
        phase = "settings"
        expected_user = os.environ["OCI_EXPECTED_USER_OCID"]
        public_origin = os.environ["PUBLIC_ORIGIN"].rstrip("/")
        origin = urlsplit(public_origin)
        if (not expected_user.startswith("ocid1.user.") or origin.scheme != "https" or not origin.netloc
                or origin.path or origin.query or origin.fragment):
            raise ValueError("invalid writer settings")
        log_startup(phase, "validated")
        phase = "oci_client"
        client = build_vault_client(os.environ.get("OCI_CONFIG_FILE", "/run/oci/config"),
                                    os.environ.get("OCI_PROFILE", "VAULT_SECRET_WRITER"), expected_user)
        phase = "application"
        app = create_app(catalog, client, public_origin)
        log_startup(phase, "ready")
        return app
    except Exception as error:
        log_startup(phase, "failed", type(error).__name__)
        raise SystemExit("Vault writer configuration is invalid; refusing to start.") from None


app = load_app() if os.environ.get("WRITER_CATALOG_FILE") else Flask(__name__)
