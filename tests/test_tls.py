"""Local certificate generation and mutual-TLS verification tests."""

import ipaddress
import ssl
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from client.errors import ClientError
from client.tls import create_client_context
from server.dev_certs import generate_development_ca, issue_client_certificate, issue_server_certificate
from server.errors import ConfigurationError
from server.tls import create_server_context

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]


class LocalCertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ca_key = self.root / "ca.key"
        self.ca_cert = self.root / "ca.crt"
        self.server_key = self.root / "server.key"
        self.server_cert = self.root / "server.crt"
        self.client_key = self.root / "client.key"
        self.client_cert = self.root / "client.crt"
        generate_development_ca(self.ca_key, self.ca_cert)
        issue_server_certificate(self.ca_key, self.ca_cert, self.server_key, self.server_cert, "localhost")
        issue_client_certificate(self.ca_key, self.ca_cert, self.client_key, self.client_cert, "demo-device")

    def test_certificates_have_correct_ca_and_usage_constraints(self):
        ca = x509.load_pem_x509_certificate(self.ca_cert.read_bytes())
        server_cert = x509.load_pem_x509_certificate(self.server_cert.read_bytes())
        client_cert = x509.load_pem_x509_certificate(self.client_cert.read_bytes())
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertFalse(server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertFalse(client_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH,
                      server_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH,
                      client_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        sans = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn(x509.DNSName("localhost"), sans)
        self.assertIn(x509.IPAddress(ipaddress.ip_address("127.0.0.1")), sans)
        self.assertIn(x509.IPAddress(ipaddress.ip_address("::1")), sans)
        # Certificate identity is device metadata only; no application role/account is encoded.
        self.assertEqual(client_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                         "demo-device")

    def test_generation_refuses_to_overwrite_any_existing_output(self):
        original = self.ca_key.read_bytes()
        with self.assertRaises(ConfigurationError):
            generate_development_ca(self.ca_key, self.root / "other-ca.crt")
        self.assertEqual(self.ca_key.read_bytes(), original)
        other_key = self.root / "other-client.key"
        other_cert = self.root / "other-client.crt"
        other_cert.write_bytes(b"preserve")
        with self.assertRaises(ConfigurationError):
            issue_client_certificate(self.ca_key, self.ca_cert, other_key, other_cert, "another-device")
        self.assertFalse(other_key.exists())
        self.assertEqual(other_cert.read_bytes(), b"preserve")

    def test_generation_rejects_repository_outputs_and_bad_ca(self):
        with self.assertRaises(ConfigurationError):
            generate_development_ca(Path(__file__).resolve().parents[1] / "bad.key",
                                     self.root / "bad.crt")
        with self.assertRaises(ConfigurationError):
            issue_server_certificate(self.root / "absent.key", self.root / "absent.crt",
                                     self.root / "x.key", self.root / "x.crt", "localhost")

    def test_tls_contexts_require_mtls_and_hostname_verification(self):
        server_context = create_server_context(self.server_cert, self.server_key, self.ca_cert)
        client_context = create_client_context(self.ca_cert, self.client_cert, self.client_key)
        self.assertEqual(server_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(client_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(client_context.check_hostname)
        self.assertGreaterEqual(server_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertGreaterEqual(client_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(len(server_context.get_ca_certs(binary_form=True)), 1)

    def test_mutual_tls_accepts_trusted_pair_and_rejects_bad_client_or_hostname(self):
        server_context = create_server_context(self.server_cert, self.server_key, self.ca_cert)
        client_context = create_client_context(self.ca_cert, self.client_cert, self.client_key)
        self.assert_tls_result(server_context, client_context, "localhost", succeeds=True)
        self.assert_tls_result(server_context, client_context, "wrong-host.invalid", succeeds=False)

        rogue_ca_key, rogue_ca_cert = self.root / "rogue-ca.key", self.root / "rogue-ca.crt"
        generate_development_ca(rogue_ca_key, rogue_ca_cert)
        untrusted_server_context = create_client_context(rogue_ca_cert, self.client_cert, self.client_key)
        self.assert_tls_result(server_context, untrusted_server_context, "localhost", succeeds=False)

        no_identity = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        no_identity.minimum_version = ssl.TLSVersion.TLSv1_2
        no_identity.load_verify_locations(cafile=str(self.ca_cert))
        self.assert_tls_result(server_context, no_identity, "localhost", succeeds=False)

        rogue_client_key, rogue_client_cert = self.root / "rogue-client.key", self.root / "rogue-client.crt"
        issue_client_certificate(rogue_ca_key, rogue_ca_cert, rogue_client_key,
                                 rogue_client_cert, "untrusted-device")
        untrusted_client_context = create_client_context(self.ca_cert, rogue_client_cert, rogue_client_key)
        self.assert_tls_result(server_context, untrusted_client_context, "localhost", succeeds=False)

        # A serverAuth-only leaf cannot authenticate as an mTLS client.
        wrong_client_key = self.root / "wrong-client.key"
        wrong_client_cert = self.root / "wrong-client.crt"
        issue_server_certificate(self.ca_key, self.ca_cert, wrong_client_key, wrong_client_cert, "localhost")
        wrong_purpose = create_client_context(self.ca_cert, wrong_client_cert, wrong_client_key)
        self.assert_tls_result(server_context, wrong_purpose, "localhost", succeeds=False)

    def assert_tls_result(self, server_context, client_context, hostname, succeeds):
        client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(client_in, client_out, server_side=False,
                                         server_hostname=hostname)
        server = server_context.wrap_bio(server_in, server_out, server_side=True)
        done = {"client": False, "server": False}
        errors = []
        for _ in range(20):
            for name, peer_input, outgoing, tls_object in (
                ("client", server_in, client_out, client),
                ("server", client_in, server_out, server),
            ):
                if done[name] or errors:
                    continue
                try:
                    tls_object.do_handshake()
                    done[name] = True
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
                except ssl.SSLError:
                    errors.append(name)
                wire_data = outgoing.read()
                if wire_data:
                    peer_input.write(wire_data)
            if errors or all(done.values()):
                break
        if succeeds:
            self.assertEqual(errors, [])
            self.assertEqual(done, {"client": True, "server": True})
        else:
            self.assertTrue(errors or not all(done.values()), "invalid TLS peer unexpectedly authenticated")

    def test_invalid_tls_context_files_fail_safely(self):
        bad = self.root / "bad.pem"
        bad.write_bytes(b"not a certificate")
        with self.assertRaises(ConfigurationError):
            create_server_context(bad, self.server_key, self.ca_cert)
        with self.assertRaises(ClientError):
            create_client_context(bad, self.client_cert, self.client_key)


if __name__ == "__main__":
    unittest.main()
