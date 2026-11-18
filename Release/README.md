# macOS release package

The release workflow builds an arm64 flat component installer for macOS 26.0 or later. The
package places `DNIeTokenHost.app` in `/Applications` and uses a fixed, version-checked bundle
replacement. It has no installer scripts. Registration, activation, clean install, upgrade and
removal require separate target validation. This package does not provide an uninstaller.

## Credential-free build

Use a clean checkout of the reviewed source, an arm64 Mac running macOS 27.2.1 build 26B131,
Xcode 27.2 build 27B52, the macOS 27.2 SDK build 26B118, Apple Swift 6.4.2 and Python 3.9 or later. Select the pinned Xcode with
`xcode-select` before running. Both the app and the extension are configured for version
`0.1.0`, build `1`.

```sh
export DNIERELEASE_REVISION="$(git rev-parse HEAD)"
make release-help
make release-check
make release-test

release_parent="$(mktemp -d /private/tmp/dnie-packages.XXXXXXXX)"
DNIERELEASE_OUTPUT="$release_parent/diagnostic" make release-unsigned
DNIERELEASE_OUTPUT="$release_parent/diagnostic" make release-verify
DNIERELEASE_OUTPUT="$release_parent/repeatability" make release-repeatability
```

The output directory must be a new canonical path outside the checkout for each build.
Verification takes the existing output directory and the same exact source revision. The
running release script must match the committed script at that revision. The
diagnostic package is unsigned at the bundle and installer level, contains no DNIe credentials
and is for local inspection. The manifests retain revision, tree, toolchain, versions, hashes
and validation status without raw tool output. Repeatability checks all files and directories
in two independent clean unsigned payloads, comparing path, type, mode and SHA-256. When
payloads differ, the check exits nonzero and records the first difference. Package hashes
identify the exact artifact produced. The measured procedure uses the pinned arm64 toolchain,
equal-width private temporary build paths and disabled compiler debug symbols. It measures
unsigned payload paths, node types, modes and file contents. Package container bytes,
filesystem extended metadata, signing timestamps and notarization tickets can differ.
Verification checks the installer BOM against the raw archive. The only accepted AppleDouble
records carry the macOS provenance attribute and must have matching expanded-file values.

The app bundle includes the unmodified GPLv3 text, the scoped public-source notices and
its exact Git revision, tree and corresponding public source URL. The URL is available
once that exact source revision is published. Inclusion of the notices does not establish
redistribution or credential authorization.

## Authorized Developer ID release

Create an independently reviewed authorization record outside the checkout before running
`make release`. The approval must cover the exact committed source, the exact credential
input and its redistribution, and submission of the credential-bearing package to Apple.
The tool validates the record's integrity and scope. The person approving the record is
responsible for establishing the grants it asserts.

Use a private, unlinked JSON file owned by the invoking user with mode `0600`. Its exact fields are
shown below. Replace all placeholders with the approved values. Git object IDs, the credential
SHA-256 and installer certificate SHA-256 use lowercase hex. The two Keychain identity SHA-1
fingerprints use uppercase hex.

```json
{
  "schema": 1,
  "scope": "public-binary-release",
  "revision": "<full Git commit ID>",
  "tree": "<full Git tree ID>",
  "version": "0.1.0",
  "build": "1",
  "source_rights": true,
  "credential_redistribution": true,
  "apple_notarization_submission": true,
  "fixture_sha256": "<authorized credential file SHA-256>",
  "team_id": "<Developer ID team ID>",
  "application_identity_sha1": "<Developer ID Application identity fingerprint>",
  "installer_identity_sha1": "<Developer ID Installer identity fingerprint>",
  "installer_certificate_sha256": "<Developer ID Installer certificate fingerprint>",
  "notary_profile": "<preconfigured Keychain profile name>"
}
```

Use Keychain Access to create certificate signing requests and install the approved Developer ID
Application and Installer certificates with their matching private keys. Both valid identities
must be in the invoking user's Keychain and match the approved team. Complete any first-use
Keychain prompt in an interactive session. An unattended run requires accessible keys and an
already configured profile under the same invoking account. Do not export either private key.

Store the notary credential interactively before running the
release. A profile name must begin with an alphanumeric character and can contain letters,
digits, dots, underscores or hyphens. The release tool accepts only the Keychain profile. Omit password and key-value options
and enter the required details in the tool's secure interactive prompts.
[Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

```sh
xcrun notarytool store-credentials "DNIeRelease"
```

```sh
export DNIERELEASE_AUTHORIZATION="/canonical/private/path/authorization.json"
export DNIERELEASE_AUTHORIZATION_SHA256="<independently approved authorization-file SHA-256>"
export DNIERELEASE_FIXTURE="/canonical/private/path/generation2.json"
export DNIERELEASE_OUTPUT="$release_parent/developer-id"
make release
make release-verify
```

The fixture must also be an owner-only unlinked regular file with mode `0600`. The workflow
checks its approved digest before copying it into private exported build trees. The two
authorized unsigned payloads must agree before any signing. The existing
staging script and the runtime fixture verifier both validate the staged input. The canonical
development fixture and staged asset are outside the workflow's write scope.

Once Apple returns a submission ID, the output directory records it privately. To resume
polling or stapling, keep that directory and the same revision/authorization inputs and run
`DNIERELEASE_RESUME=1 make release`. The fixture is only needed when starting a release.
If there is no recorded submission ID, resume stops for manual investigation. It also
stops on a reported Apple rejection. A tool failure without a confirmed result leaves the
status unresolved. Preserve the private state while investigating either outcome.

`DNIeToken.pkg` is complete after the final manifest records Developer ID signing, Apple
acceptance, ticket validation and Gatekeeper acceptance. It remains unverified on a clean
target until the separate lifecycle checks pass. Keep submission artifacts and records in
the private output directory. Do not commit them.
