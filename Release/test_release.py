import gzip
import hashlib
import struct
import json
import os
import plistlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid
from types import SimpleNamespace

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def test_source_rejects_dirty_checkout_and_revision_mismatch(self):
        def git(*args):
            return subprocess.check_output(["/usr/bin/git", "-C", self.root, *args],
                                           stderr=subprocess.DEVNULL,
                                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                                "GIT_CONFIG_NOSYSTEM": "1",
                                                "GIT_CONFIG_GLOBAL": "/dev/null"}).decode().strip()
        git("init", "-q", "--template=")
        (self.root / "source").touch()
        git("add", "source")
        git("-c", "user.name=Release Test", "-c", "user.email=test@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "test")
        rev = git("rev-parse", "HEAD")
        self.assertEqual(release.source_identity(self.root, rev),
                         {"revision": rev, "tree": git("rev-parse", "HEAD^{tree}")})
        for rev_arg in ("HEAD", rev[:8], "1" * 40):
            with self.assertRaises(release.ReleaseError):
                release.source_identity(self.root, rev_arg)
        (self.root / "untracked").touch()
        with self.assertRaisesRegex(release.ReleaseError, "dirty"):
            release.source_identity(self.root, rev)

    def test_tool_drift_fails_preflight(self):
        runner = Mock(side_effect=["Xcode 27.2\nBuild version 27B52\n", "27.3\n",
                                   "Apple Swift version 6.4.2\n"])
        with self.assertRaisesRegex(release.ReleaseError, "SDK"):
            release.check_toolchain(runner, "arm64")

    def test_sensitive_file_rejects_links_and_shared_permissions(self):
        path = self.root / "input"
        path.write_bytes(b"dummy")
        path.chmod(0o644)
        with self.assertRaises(release.ReleaseError):
            release.read_private(path)
        path.chmod(0o600)
        self.assertEqual(release.read_private(path), b"dummy")
        for create_link in (lambda link: link.symlink_to(path), lambda link: os.link(path, link)):
            link = self.root / "link"
            create_link(link)
            with self.assertRaises(release.ReleaseError):
                release.read_private(link)
            link.unlink()

    def test_authorization_is_exact_default_closed_and_bound_to_fixture(self):
        path = self.root / "permission"
        fixture = hashlib.sha256(b"test fixture").hexdigest()
        source = {"revision": "2" * 40, "tree": "3" * 40}
        record = {
            "schema": 1,
            **source,
            "scope": "public-binary-release",
            "version": "0.1.0",
            "build": "1",
            "source_rights": True,
            "credential_redistribution": True,
            "apple_notarization_submission": True,
            "fixture_sha256": fixture,
            "team_id": "Z5X0A1B2C3",
            "application_identity_sha1": "A" * 40,
            "installer_identity_sha1": "B" * 40,
            "installer_certificate_sha256": "c" * 64,
            "notary_profile": "release-test",
        }

        def verify(record, expected=None, fixture_hash=fixture):
            data = json.dumps(record).encode()
            path.write_bytes(data)
            path.chmod(0o600)
            digest = hashlib.sha256(data).hexdigest()
            return release.authorize(path, expected or digest, source, fixture_hash)

        self.assertEqual(verify(record)["team_id"], "Z5X0A1B2C3")
        for key in ("source_rights", "credential_redistribution", "apple_notarization_submission"):
            with self.subTest(key=key), self.assertRaises(release.ReleaseError):
                verify({**record, key: False})
        for key, value in (("revision", "1" * 40), ("tree", "1" * 40),
                           ("notary_profile", "--password"),
                           ("password", "unrecognized-field")):
            with self.subTest(key=key), self.assertRaises(release.ReleaseError):
                verify({**record, key: value})
        with self.assertRaises(release.ReleaseError):
            verify(record, expected="f" * 64)
        with self.assertRaises(release.ReleaseError):
            verify(record, fixture_hash="f" * 64)

    def test_inventory_rejects_link_and_first_difference_includes_file_mode(self):
        path = self.root / "item"
        path.touch(mode=0o644)
        original = release.inventory(self.root)
        path.chmod(0o600)
        self.assertEqual(release.first_difference(original, release.inventory(self.root)),
                         {"path": "item", "field": "mode"})
        (self.root / "link").symlink_to(path)
        with self.assertRaises(release.ReleaseError):
            release.inventory(self.root)

    def test_signature_verification_rejects_unexpected_entitlement(self):
        with self.assertRaises(release.ReleaseError):
            release.check_entitlements(
                {"com.apple.security.smartcard": True, "get-task-allow": True}, extension=True
            )
        with self.assertRaises(release.ReleaseError):
            release.check_entitlements({"com.apple.security.smartcard": 1}, extension=True)
        release.check_entitlements({"com.apple.security.app-sandbox": True,
                                    "com.apple.security.smartcard": True}, extension=True)


    def test_identity_selection_rejects_wrong_team(self):
        identities = '  1) ' + 'A' * 40 + ' "Developer ID Application: Test (Z5X0A1B2C3)"'
        with self.assertRaises(release.ReleaseError):
            release.select_identity(identities, "A" * 40, "Developer ID Application", "X5X0A1B2C3")

    def test_payload_rejects_unreviewed_embedded_code(self):
        for name, kind in release.payload_paths(False, False).items():
            if kind == "file":
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
        (self.root / "DNIeTokenHost.app/Contents/extra.dylib").touch()
        with self.assertRaisesRegex(release.ReleaseError, "allowlist"):
            release.check_payload(self.root, {"revision": "2" * 40, "tree": "3" * 40})

    def test_strict_signatures_and_timestamp_are_required(self):
        auth = {"team_id": "Z5X0A1B2C3", "application_identity_sha1": "A" * 40}
        good_detail = "CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+1\nTimestamp=09:00\n"
        for detail in (good_detail.replace("runtime", "adhoc"),
                       good_detail.replace("Timestamp=", "Signed=")):
            runner = Mock(side_effect=["", "", detail])
            with self.assertRaisesRegex(release.ReleaseError, "hardened runtime"):
                release.verify_application_signature(self.root, auth, runner)
        extension_entitlements = {
            "com.apple.security.app-sandbox": True, "com.apple.security.smartcard": True,
        }
        runner = Mock(side_effect=["", "", good_detail, b"", "", good_detail,
                                   plistlib.dumps(extension_entitlements)])
        release.verify_application_signature(self.root, auth, runner)
        self.assertEqual(runner.call_count, 7)
        for entitlement_call in (runner.call_args_list[3], runner.call_args_list[6]):
            self.assertIn("--xml", entitlement_call.args[0])
        for cert_requirement_call in (runner.call_args_list[1], runner.call_args_list[4]):
            self.assertIn('certificate leaf = H"' + 'A' * 40 + '"',
                          cert_requirement_call.args[0][4])

    def test_installer_signature_requires_expected_certificate_fingerprint(self):
        auth = {"team_id": "Z5X0A1B2C3", "installer_certificate_sha256": "ab" * 32}
        detail = ("Status: signed by a developer certificate issued by Apple for distribution.\n"
                  "   Signed with a trusted timestamp on: 2026-11-18 10:00:00 +0000\n"
                  "Certificate Chain:\n 1. Developer ID Installer: Test (Z5X0A1B2C3)\n"
                  "    SHA256 Fingerprint:\n        " + "AB " * 15 + "AB\n        "
                  + "AB " * 15 + "AB\n")
        release.verify_installer_signature(self.root / "package.pkg", auth, Mock(return_value=detail))
        for bad_detail in (detail.replace("Z5X0A1B2C3", "X5X0A1B2C3"),
                           detail.replace("AB", "CD", 1),
                           detail.replace("Signed with a trusted timestamp", "Signed without a timestamp"),
                           detail.replace("Developer ID Installer", "Developer ID Application")):
            with self.assertRaisesRegex(release.ReleaseError, "unexpected"):
                release.verify_installer_signature(self.root / "package.pkg", auth,
                                                   Mock(return_value=bad_detail))

    def test_signed_verification_rejects_manifest_rebound_to_another_payload(self):
        identity = {"revision": "2" * 40, "tree": "3" * 40}
        binding = {"source": identity, "authorization_sha256": "a" * 64,
                   "submission_sha256": "b" * 64, "payload_sha256": "c" * 64,
                   "package_sha256": "d" * 64, "unsigned_payload_sha256": "e" * 64}
        final = {"schema": 1, "kind": "developer-id-release", "source": identity,
                 "configuration": release.CONFIG, "toolchain": release.TOOLCHAIN,
                 "submission_sha256": binding["submission_sha256"],
                 "payload_sha256": binding["payload_sha256"], "package_sha256": binding["package_sha256"],
                 "unsigned_payload_sha256": binding["unsigned_payload_sha256"],
                 "validation": {"credential": "verified", "build": "Developer ID", "package": "inspected",
                                "notarization": "accepted", "stapled_ticket": "validated",
                                "gatekeeper": "accepted", "runtime": "unverified", "repeatability": "identical"}}
        args = SimpleNamespace(authorization=None, authorization_sha256="a" * 64)
        state = {"status": "accepted", "sha256": binding["submission_sha256"],
                 "id": str(uuid.UUID(int=17))}
        release.write_record(self.root / release.NOTARY_STATE, state)
        for key in ("payload_sha256", "package_sha256", "unsigned_payload_sha256"):
            release.write_record(self.root / release.MANIFEST, {**final, key: "0" * 64})
            with patch.object(release, "authorize", return_value={"fixture_sha256": "f" * 64}), \
                 patch.object(release, "load_binding", return_value=binding), \
                 patch.object(release, "private_artifact_hash", return_value=final["package_sha256"]), \
                 patch.object(release, "inspect_package") as inspect:
                with self.subTest(key=key), self.assertRaisesRegex(release.ReleaseError, "binding"):
                    release.verify_output(self.root, identity, args)
                inspect.assert_not_called()

    def test_notices_require_exact_bytes_and_exact_source_reference(self):
        identity = {"revision": "2" * 40, "tree": "3" * 40}
        reference = {
            "revision": "2" * 40, "tree": "3" * 40,
            "url": "https://github.com/emcrisostomo/dnie-macos/tree/" + "2" * 40,
        }
        license_path = "DNIeTokenHost.app/Contents/Resources/LICENSE"
        notice_path = "DNIeTokenHost.app/Contents/Resources/LICENSES/README.md"
        source_path = "DNIeTokenHost.app/Contents/Resources/SOURCE.json"
        for path in (license_path, notice_path, source_path):
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_text("placeholder")
        contents = {license_path: {"sha256": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"},
                    notice_path: {"sha256": "5217a4b4d17dfc3fd3243fdbc53d2af19e4ecd1d770725b79e1d98429c4e85c2"}}
        (self.root / source_path).write_text(json.dumps(reference))
        release.verify_notices(self.root, contents, identity)
        (self.root / source_path).write_text(json.dumps({**reference, "tree": "0" * 40}))
        with self.assertRaisesRegex(release.ReleaseError, "source"):
            release.verify_notices(self.root, contents, identity)
        (self.root / source_path).write_text(json.dumps(reference))
        contents[license_path]["sha256"] = "0" * 64
        with self.assertRaisesRegex(release.ReleaseError, "licence"):
            release.verify_notices(self.root, contents, identity)

    def test_payload_mode_normalization_is_exact_and_local(self):
        unrelated = self.root / "private-fixture"
        unrelated.touch(mode=0o600)
        payload = self.root / "payload"
        for name, kind in release.payload_paths(True, False).items():
            node = payload / name
            if kind == "file":
                node.parent.mkdir(parents=True, exist_ok=True)
                node.touch(mode=0o600)
        release.normalize_unsigned_modes(payload, credential=True)
        items = release.inventory(payload)
        self.assertEqual(items["DNIeTokenHost.app"]["mode"], "0755")
        self.assertEqual(items["DNIeTokenHost.app/Contents/MacOS/DNIeTokenHost"]["mode"], "0755")
        credential = next(path for path in items if path.endswith("/Assets/generation2.json"))
        self.assertEqual(items[credential]["mode"], "0644")
        self.assertEqual(unrelated.stat().st_mode & 0o777, 0o600)
        (payload / credential).chmod(0o600)
        with self.assertRaisesRegex(release.ReleaseError, "mode"):
            release.check_payload(payload, {"revision": "2" * 40, "tree": "3" * 40},
                                  fixture_hash="f" * 64)

    def test_finalize_resume_does_not_first_submit_without_state(self):
        identity = {"revision": "2" * 40, "tree": "3" * 40}
        artifact = self.root / release.SUBMISSION
        artifact.touch(mode=0o600)
        binding = {"source": identity, "authorization_sha256": "a" * 64,
                   "submission_sha256": hashlib.sha256(b"").hexdigest(),
                   "payload_sha256": hashlib.sha256(b"{}").hexdigest(), "unsigned_payload_sha256": "c" * 64}
        release.write_record(self.root / "release-binding.json", binding)
        network = Mock()
        real_notarize = release.notarize

        def interrupted_notary(output, pkg, profile, **kwargs):
            return real_notarize(output, pkg, profile, network, **kwargs)

        auth = {"fixture_sha256": "f" * 64, "notary_profile": "release-test"}
        with patch.object(release, "inspect_package", return_value={}), \
             patch.object(release, "notarize", side_effect=interrupted_notary):
            with self.assertRaisesRegex(release.ReleaseError, "recorded notary submission"):
                release.finalize_release(identity, self.root, auth, "a" * 64, resume=True)
        network.assert_not_called()
        self.assertFalse((self.root / release.NOTARY_STATE).exists())
        self.assertFalse((self.root / release.SIGNED_PACKAGE).exists())

    def test_package_metadata_rejects_extra_upgrade_target_and_version_drift(self):
        for node in ("Bom", "Payload"):
            (self.root / node).touch()
        metadata = self.root / "PackageInfo"
        package_info = """<pkg-info overwrite-permissions="true" relocatable="false"
          identifier="org.dniemacos.dnietoken.installer" postinstall-action="none"
          version="0.1.0.1" format-version="2" generator-version="InstallCmds-Test"
          install-location="/Applications" auth="root">
          <payload numberOfFiles="45" installKBytes="2010"/>
          <bundle id="dniecore.DNIeCore.resources"
            path="./DNIeTokenHost.app/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle"/>
          <bundle id="org.dniemacos.dnietoken" path="./DNIeTokenHost.app"
            CFBundleShortVersionString="0.1.0" CFBundleVersion="1"/>
          <bundle id="org.dniemacos.dnietoken.tokenextension"
            path="./DNIeTokenHost.app/Contents/PlugIns/DNIeTokenExtension.appex"
            CFBundleShortVersionString="0.1.0" CFBundleVersion="1"/>
          <bundle-version><bundle id="org.dniemacos.dnietoken"/></bundle-version>
          <upgrade-bundle><bundle id="org.dniemacos.dnietoken"/></upgrade-bundle>
          <update-bundle/><atomic-update-bundle/>
          <strict-identifier><bundle id="org.dniemacos.dnietoken"/></strict-identifier>
          <relocate/>
        </pkg-info>"""
        metadata.write_text(package_info)
        release.check_package_metadata(self.root)
        for altered in (
                package_info.replace("</upgrade-bundle>", '<bundle id="other"/></upgrade-bundle>'),
                package_info.replace('CFBundleVersion="1"', 'CFBundleVersion="2"'),
                package_info.replace("<relocate/>", "<relocate/><unexpected/>"),
                package_info.replace('install-location="/Applications"', 'install-location="/tmp"')):
            metadata.write_text(altered)
            with self.assertRaises(release.ReleaseError):
                release.check_package_metadata(self.root)

    def test_torn_notary_state_cannot_trigger_submission(self):
        artifact = self.root / "submission.pkg"
        artifact.touch(mode=0o600)
        state = self.root / release.NOTARY_STATE
        network = Mock()
        release.write_record(state, {"sha256": hashlib.sha256(b"").hexdigest(),
                                     "status": "uploaded", "id": None})
        with self.assertRaises(release.ReleaseError):
            release.notarize(self.root, artifact, "release-test", network, resume=True)
        network.assert_not_called()

    def test_manifest_rejects_null_validation_and_boolean_schema(self):
        identity = {"revision": "2" * 40, "tree": "3" * 40}
        record = {"schema": 1, "kind": "credential-free-diagnostic", "source": identity,
                  "configuration": release.CONFIG, "toolchain": release.TOOLCHAIN,
                  "package_sha256": "a" * 64, "payload_sha256": "b" * 64,
                  "validation": {"credential": "absent", "build": "unsigned", "package": "inspected",
                                 "notarization": "not attempted", "runtime": "unverified",
                                 "repeatability": "not attempted"}}
        path = self.root / release.MANIFEST
        release.write_record(path, record)
        self.assertEqual(release.read_manifest(path, identity), record)
        for bad in ({"schema": True}, {"validation": None}):
            release.write_record(path, {**record, **bad})
            with self.assertRaises(release.ReleaseError):
                release.read_manifest(path, identity)

    def test_output_parent_checks_all_ancestors_before_use(self):
        unsafe = self.root / "unsafe"
        safe = unsafe / "parent"
        safe.mkdir(parents=True)
        output = safe / "release"
        release.validate_output_parent(output)
        unsafe.chmod(0o777)
        with self.assertRaises(release.ReleaseError):
            release.validate_output_parent(output)
        self.assertFalse(output.exists())

    def test_raw_archive_accounts_for_bom_and_rejects_malformed_metadata(self):
        def record(name, mode, data=b"", uid=0, links=1):
            name = name.encode() + b"\0"
            head = (f"070707{0:06o}{1:06o}{mode:06o}{uid:06o}{0:06o}{links:06o}{0:06o}"
                    f"{0:011o}{len(name):06o}{len(data):011o}").encode()
            return head + name + data

        provenance = b"01234567890"
        companion = (
            struct.pack(">II16sHIIIIII", 0x51607, 0x20000, b"Mac OS X        ", 2,
                        9, 50, 113, 2, 163, 0) + b"\0" * 34
            + struct.pack(">8I2HIIHB", 0x41545452, 0, 163, 152, 11, 0, 0, 0, 0, 1,
                          152, 11, 0, 21)
            + b"com.apple.provenance\0" + provenance
        )
        layout = {"item": "file"}
        bom = ".\t40755\t0\t0\n./item\t100644\t0\t0\n./._item\t100644\t0\t0\n"
        raw = self.root / "Payload"
        header = record(".", 0o40755) + record("./item", 0o100644, b"test")
        trailer = record("TRAILER!!!", 0)
        raw.write_bytes(gzip.compress(header + record("./._item", 0o100644, companion) + trailer))
        digests, attrs = release.check_raw_payload(raw, bom, layout, 3)
        self.assertEqual(digests, {"item": hashlib.sha256(b"test").hexdigest()})
        self.assertEqual(attrs, {"item": provenance})
        for invalid in (
                header + record("./._item", 0o100644, companion.replace(b"provenance", b"provEnance")) + trailer,
                header + record("./._other", 0o100644, companion) + trailer,
                header + record("./._item", 0o100644, companion, uid=501) + trailer,
                header + record("./._item", 0o100644, companion, links=2) + trailer,
                header + record("./._item", 0o100644, companion) + trailer + b"x"):
            raw.write_bytes(gzip.compress(invalid))
            with self.assertRaises(release.ReleaseError):
                release.check_raw_payload(raw, bom, layout, 3)
        raw.write_bytes(gzip.compress(header + record("./._item", 0o100644, companion) + trailer))
        for wrong_bom in (bom.replace("100644", "100755"),
                          bom.replace("./item", "./different"),
                          bom + "./item\t100644\t0\t0\n"):
            with self.assertRaises(release.ReleaseError):
                release.check_raw_payload(raw, wrong_bom, layout, 3)

    def test_expanded_attribute_must_equal_the_archive_attribute(self):
        item = self.root / "item"
        item.touch()
        contents = {"item": {"type": "file", "sha256": hashlib.sha256(b"").hexdigest()}}
        attrs = {"item": b"01234567890"}
        digests = {"item": hashlib.sha256(b"").hexdigest()}
        names = ["", "com.apple.provenance\n"]
        release.check_expanded_archive(self.root, contents, digests, attrs,
                                       Mock(side_effect=[*names, attrs["item"].hex()]))
        for replies in (["", "com.apple.provenance\ncom.apple.FinderInfo\n"],
                        [*names, b"11234567890".hex()]):
            with self.assertRaises(release.ReleaseError):
                release.check_expanded_archive(self.root, contents, digests, attrs,
                                               Mock(side_effect=replies))

    def test_running_program_must_match_exact_committed_bytes(self):
        script = Path(release.__file__).resolve().read_bytes()
        with patch.object(release, "git", return_value=script):
            release.check_running_program(self.root, "a" * 40)
        with patch.object(release, "git", return_value=script + b"\n"):
            with self.assertRaisesRegex(release.ReleaseError, "pinned source revision"):
                release.check_running_program(self.root, "a" * 40)

    def test_main_rejects_missing_approval_and_fixture_mismatch_before_output(self):
        output = self.root / "release-output"
        source = self.root / "checkout"
        source.mkdir()
        args = SimpleNamespace(operation="release", source=source, revision="a" * 40,
                               output=output, resume=False, authorization=None,
                               authorization_sha256=None, fixture=self.root / "dummy-fixture")
        identity = {"revision": args.revision, "tree": "b" * 40}
        args.fixture.write_bytes(b"synthetic")
        args.fixture.chmod(0o600)
        with patch.object(release, "arguments", return_value=args), \
             patch.object(release, "source_identity", return_value=identity), \
             patch.object(release, "source_tree"), patch.object(release, "check_running_program"), \
             patch.object(release, "check_toolchain"), patch.object(release, "start_release") as start, \
             patch.object(release.os, "umask"), patch.object(release.signal, "signal"):
            with self.assertRaisesRegex(release.ReleaseError, "approved authorization"):
                release.main()
            with patch.object(release, "authorize", return_value={"fixture_sha256": "f" * 64}):
                with self.assertRaisesRegex(release.ReleaseError, "credential input digest"):
                    release.main()
            start.assert_not_called()
            self.assertFalse(output.exists())

    def test_authorized_build_mismatch_cannot_sign(self):
        identity = {"revision": "a" * 40, "tree": "b" * 40}
        auth = {"fixture_sha256": "f" * 64}
        first = {"item": {"type": "file", "mode": "0644", "sha256": "c" * 64}}
        second = {"item": {"type": "file", "mode": "0644", "sha256": "d" * 64}}
        with patch.object(release, "signing_identities", return_value=("app", "pkg")), \
             patch.object(release, "build_payload", return_value=self.root) as build, \
             patch.object(release, "check_payload", side_effect=[first, second]), \
             patch.object(release, "sign_application") as sign:
            with self.assertRaisesRegex(release.ReleaseError, "Unsigned release payloads differ"):
                release.start_release(self.root, identity, None, self.root, auth, "e" * 64,
                                      b"synthetic")
            self.assertEqual(build.call_count, 2)
            self.assertEqual(build.call_args_list[0].args[-1], build.call_args_list[1].args[-1])
            sign.assert_not_called()
            self.assertFalse((self.root / release.SUBMISSION).exists())

    def test_failed_submission_cannot_be_retried(self):
        artifact = self.root / "submission.pkg"
        artifact.touch(mode=0o600)
        runner = Mock(side_effect=release.ReleaseError("transport unavailable"))
        for _ in range(2):
            with self.assertRaises(release.ReleaseError):
                release.notarize(self.root, artifact, "release-test", runner)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(artifact.read_bytes(), b"")

    def test_resume_uses_same_submission_and_never_uploads_again(self):
        artifact = self.root / "submission.pkg"
        artifact.touch(mode=0o600)
        identifier = str(uuid.UUID(int=17))
        initial = Mock(side_effect=[json.dumps({"id": identifier, "message": "accepted upload"}),
                                    release.ReleaseError("wait interrupted")])
        with self.assertRaises(release.ReleaseError):
            release.notarize(self.root, artifact, "release-test", initial)
        verify = Mock(return_value=json.dumps({"id": identifier, "status": "Accepted"}))
        self.assertEqual(release.notarize(self.root, artifact, "release-test", verify), identifier)
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(verify.call_args.args[0][1:4], ("notarytool", "wait", identifier))
        artifact.write_bytes(b"changed upload")
        with self.assertRaises(release.ReleaseError):
            release.notarize(self.root, artifact, "release-test", verify)
        self.assertEqual(verify.call_count, 1)

    def test_rejected_notarization_is_terminal(self):
        artifact = self.root / "submission.pkg"
        artifact.touch(mode=0o600)
        identifier = str(uuid.UUID(int=17))
        failure = Mock(side_effect=[json.dumps({"id": identifier, "message": "accepted upload"}),
                                    json.dumps({"id": identifier, "status": "Invalid"})])
        with self.assertRaises(release.ReleaseError):
            release.notarize(self.root, artifact, "release-test", failure)
        with self.assertRaises(release.ReleaseError):
            release.notarize(self.root, artifact, "release-test", failure)
        self.assertEqual(failure.call_count, 2)


if __name__ == "__main__":
    unittest.main()
