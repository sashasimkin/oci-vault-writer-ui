import hashlib
import html
import io
import json
import os
import re
import sys
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from unittest.mock import patch

import server


class CatalogTests(unittest.TestCase):
    def test_catalog_is_validated_and_browser_view_omits_ocids(self):
        item = {
            "example_secret": {
                "id": "ocid1.vaultsecret.test.unique",
                "name": "example-secret",
                "description": "Synthetic test secret",
            }
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(item), encoding="utf-8")
            catalog = server.load_catalog(str(path))

        client = server.create_app(catalog, object(), "https://vault-writer.example").test_client()
        body = client.get("/").get_data(as_text=True)
        self.assertIn(item["example_secret"]["name"], body)
        self.assertNotIn(item["example_secret"]["id"], body)

    def test_catalog_rejects_non_vault_id(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps({"x": {"id": "ocid1.user.fake", "name": "x"}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                server.load_catalog(str(path))

    def test_empty_catalog_fails_closed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                server.load_catalog(str(path))


class WriteTests(unittest.TestCase):
    def test_writer_posts_base64_current_version(self):
        captured = {}

        class FakeResponse:
            data = types.SimpleNamespace(current_version_number=9)

        class FakeClient:
            def update_secret(self, secret_id, details, *, opc_request_id, retry_strategy):
                captured.update(
                    secret_id=secret_id,
                    details=details,
                    opc_request_id=opc_request_id,
                    retry_strategy=retry_strategy,
                )
                return FakeResponse()

        fake_models = types.SimpleNamespace(
            UpdateSecretDetails=lambda **kwargs: types.SimpleNamespace(**kwargs),
            Base64SecretContentDetails=lambda **kwargs: types.SimpleNamespace(**kwargs),
        )
        fake_oci = types.SimpleNamespace(
            vault=types.SimpleNamespace(models=fake_models),
            retry=types.SimpleNamespace(NoneRetryStrategy=lambda: "no-retry"),
        )
        secret = {"id": "ocid1.vaultsecret.test.unique", "name": "example"}
        with patch.dict(sys.modules, {"oci": fake_oci}):
            version = server.update_secret(
                FakeClient(), secret, "synthetic test fixture", "test_secret", "operation-safe-123"
            )

        self.assertEqual(version, 9)
        self.assertEqual(captured["secret_id"], secret["id"])
        content = captured["details"].secret_content
        self.assertIs(captured["details"].enable_auto_generation, False)
        self.assertEqual(content.stage, "CURRENT")
        self.assertEqual(content.content, "c3ludGhldGljIHRlc3QgZml4dHVyZQ==")
        self.assertEqual(captured["retry_strategy"], "no-retry")
        self.assertEqual(captured["opc_request_id"], "operation-safe-123")
        self.assertNotIn("synthetic test fixture", json.dumps({"version": version}))

    def test_writer_logs_safe_request_shape_and_success_metadata(self):
        sentinel = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_LOG"

        class FakeResponse:
            status = 200
            data = types.SimpleNamespace(current_version_number=12)

        class FakeClient:
            def update_secret(self, *args, **kwargs):
                return FakeResponse()

        fake_models = types.SimpleNamespace(
            UpdateSecretDetails=lambda **kwargs: types.SimpleNamespace(**kwargs),
            Base64SecretContentDetails=lambda **kwargs: types.SimpleNamespace(**kwargs),
        )
        fake_oci = types.SimpleNamespace(
            vault=types.SimpleNamespace(models=fake_models),
            retry=types.SimpleNamespace(NoneRetryStrategy=lambda: "no-retry"),
        )
        handler = server.WRITE_LOGGER.handlers[0]
        original_stream = handler.stream
        stream = io.StringIO()
        handler.setStream(stream)
        try:
            with (
                patch.dict(sys.modules, {"oci": fake_oci}),
                patch.dict(os.environ, {"WRITER_DEBUG_DIAGNOSTICS": "true"}),
            ):
                version = server.update_secret(
                    FakeClient(), {"id": "ocid1.vaultsecret.test.unique"}, sentinel,
                    "test_secret", "operation-safe-123",
                )
        finally:
            handler.setStream(original_stream)

        output = stream.getvalue()
        self.assertEqual(version, 12)
        self.assertNotIn(sentinel, output)
        self.assertNotIn(server.base64.b64encode(sentinel.encode()).decode(), output)
        self.assertIn("writer_write_request operation_id=operation-safe-123", output)
        self.assertIn("payload_size=0_256 base64_valid=true", output)
        self.assertIn("content_type=BASE64 stage=CURRENT", output)
        self.assertIn("request_fields=secretContent,contentType,name,stage,content", output)
        self.assertIn("writer_write outcome=confirmed operation_id=operation-safe-123", output)
        self.assertIn("http_status=200 current_version_number=12", output)


class HttpBoundaryTests(unittest.TestCase):
    def request(self, payload):
        catalog = {
            "test_secret": {
                "id": "ocid1.vaultsecret.test.unique",
                "name": "synthetic-test-target",
                "description": "not a real credential",
            }
        }
        client = server.create_app(catalog, object(), "https://vault-writer.example").test_client()
        response = client.post(
            "/api/write", data=payload,
            headers={"Host": "vault-writer.example", "Origin": "https://vault-writer.example"},
        )
        return response.status_code, response.get_data(as_text=True)

    def test_success_response_contains_no_submitted_value(self):
        with patch.object(server, "update_secret", return_value=7):
            status, body = self.request({"alias": "test_secret", "value": "synthetic-not-a-secret"})
        self.assertEqual(status, 200)
        self.assertIn("7", body)
        self.assertNotIn("synthetic-not-a-secret", body)

    def test_oci_exception_is_suppressed(self):
        with patch.object(server, "update_secret", side_effect=RuntimeError("synthetic-not-a-secret")):
            status, body = self.request({"alias": "test_secret", "value": "synthetic-not-a-secret"})
        self.assertEqual(status, 200)
        self.assertNotIn("synthetic-not-a-secret", body)

    def test_debug_write_failure_logs_details_but_redacts_submitted_value(self):
        sentinel = 'SYNTHETIC/PRIVATE+<VALUE>&"DO_NOT_LOG'
        encoded = server.base64.b64encode(sentinel.encode()).decode()
        escaped = quote(sentinel, safe="")
        html_encoded = html.escape(sentinel, quote=True)
        json_encoded = json.dumps(sentinel, ensure_ascii=True)[1:-1]

        class SyntheticServiceError(Exception):
            code = "NotAuthorizedOrNotFound"
            status = 403
            request_id = "request-safe-123"
            headers = {
                "authorization": sentinel,
                "content-type": "application/json",
                "x-debug": encoded,
            }
            message = (
                f"Invalid secretContent contentType: {sentinel}; base64={encoded}; "
                f"url={escaped}; html={html_encoded}; json={json_encoded}"
            )

        with (
            patch.dict(os.environ, {"WRITER_DEBUG_DIAGNOSTICS": "true"}),
            patch.object(server, "update_secret", side_effect=SyntheticServiceError(sentinel)),
            self.assertLogs("vault_writer.write", level="WARNING") as captured,
        ):
            status, body = self.request({"alias": "test_secret", "value": sentinel})

        output = "\n".join(captured.output)
        self.assertEqual(status, 200)
        self.assertNotIn(sentinel, body)
        self.assertNotIn(sentinel, output)
        self.assertNotIn(encoded, output)
        self.assertNotIn(escaped, output)
        self.assertNotIn(html_encoded, output)
        self.assertNotIn(json_encoded, output)
        self.assertIn("secret_sha256=" + hashlib.sha256(sentinel.encode()).hexdigest(), output)
        operation_id = re.search(r"operation_id=([a-f0-9]{32})", output)
        self.assertIsNotNone(operation_id)
        self.assertIn(operation_id.group(1), body)
        self.assertIn("writer_write outcome=unconfirmed", output)
        self.assertIn("alias=test_secret", output)
        self.assertIn("error_type=SyntheticServiceError", output)
        self.assertIn("error_code=NotAuthorizedOrNotFound", output)
        self.assertIn("error_fields=secretContent,contentType", output)
        self.assertIn("error_hints=invalid", output)
        self.assertIn("http_status=403", output)
        self.assertIn("oci_request_id=request-safe-123", output)
        self.assertIn('"content-type":"application/json"', output)
        self.assertIn("response_headers=", output)
        self.assertIn("service_message=", output)
        self.assertIn("****", output)
        header_match = re.search(r"response_headers=(\{.*\})$", output)
        self.assertIsNotNone(header_match)
        self.assertEqual(json.loads(header_match.group(1))["authorization"], "****")
        self.assertEqual(json.loads(header_match.group(1))["x-debug"], "****")

    def test_oci_sdk_serializes_secret_update_body_to_expected_schema(self):
        from oci.base_client import BaseClient
        from oci.vault.models import UpdateSecretDetails, Base64SecretContentDetails, vault_type_mapping

        details = UpdateSecretDetails(
            secret_content=Base64SecretContentDetails(
                content_type="BASE64", name="test-version", stage="CURRENT", content="YWJj"
            )
        )
        serializer = object.__new__(BaseClient)
        serializer.complex_type_mappings = vault_type_mapping

        self.assertEqual(
            serializer.sanitize_for_serialization(details),
            {"secretContent": {
                "contentType": "BASE64", "name": "test-version", "stage": "CURRENT", "content": "YWJj"
            }},
        )

    def test_request_cannot_choose_an_unlisted_secret(self):
        with patch.object(server, "update_secret") as update:
            status, _ = self.request({"alias": "arbitrary_ocid", "value": "synthetic"})
        self.assertEqual(status, 400)
        update.assert_not_called()


class StartupDiagnosticsTests(unittest.TestCase):
    def test_debug_startup_diagnostics_never_log_configuration_values(self):
        sentinel = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_LOG"
        catalog = {
            "test_secret": {
                "id": f"ocid1.vaultsecret.{sentinel}",
                "name": sentinel,
                "description": "synthetic",
            }
        }
        environment = {
            "WRITER_DEBUG_DIAGNOSTICS": "true",
            "WRITER_CATALOG_FILE": f"/private/{sentinel}/catalog.json",
            "OCI_EXPECTED_USER_OCID": f"ocid1.user.{sentinel}",
            "PUBLIC_ORIGIN": "https://writer.example.test",
            "OCI_CONFIG_FILE": f"/private/{sentinel}/config",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(server, "load_catalog", return_value=catalog),
            patch.object(server, "build_vault_client", return_value=object()),
            self.assertLogs("vault_writer", level="INFO") as captured,
        ):
            server.load_app()

        output = "\n".join(captured.output)
        self.assertIn("writer_startup phase=catalog outcome=ready", output)
        self.assertIn("writer_startup phase=settings outcome=validated", output)
        self.assertNotIn(sentinel, output)

    def test_startup_failure_logs_only_phase_and_exception_type(self):
        sentinel = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_LOG"
        environment = {
            "WRITER_DEBUG_DIAGNOSTICS": "true",
            "WRITER_CATALOG_FILE": "/private/catalog.json",
            "OCI_EXPECTED_USER_OCID": "ocid1.user.synthetic",
            "PUBLIC_ORIGIN": "https://writer.example.test",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(server, "load_catalog", side_effect=RuntimeError(sentinel)),
            self.assertLogs("vault_writer", level="ERROR") as captured,
            self.assertRaises(SystemExit),
        ):
            server.load_app()

        output = "\n".join(captured.output)
        self.assertIn("writer_startup outcome=failed phase=catalog", output)
        self.assertIn("error_type=RuntimeError", output)
        self.assertNotIn(sentinel, output)


if __name__ == "__main__":
    unittest.main()
