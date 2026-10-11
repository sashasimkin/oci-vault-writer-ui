import json
import os
import sys
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
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
            def update_secret(self, secret_id, details, **kwargs):
                captured.update(secret_id=secret_id, details=details, kwargs=kwargs)
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
            version = server.update_secret(FakeClient(), secret, "synthetic test fixture", "test_secret")

        self.assertEqual(version, 9)
        self.assertEqual(captured["secret_id"], secret["id"])
        content = captured["details"].secret_content
        self.assertEqual(content.stage, "CURRENT")
        self.assertEqual(content.content, "c3ludGhldGljIHRlc3QgZml4dHVyZQ==")
        self.assertEqual(captured["kwargs"]["retry_strategy"], "no-retry")
        self.assertNotIn("synthetic test fixture", json.dumps({"version": version}))


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
        self.assertIn("writer_startup phase=oci_client outcome=ready", output)
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
