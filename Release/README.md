# macOS release package

The release workflow builds an arm64 flat component installer for macOS 26.0 or later. The
package places `DNIeTokenHost.app` in `/Applications` and uses a fixed, version-checked bundle
replacement. It has no installer scripts. Registration, activation, clean install, upgrade and
removal require separate target validation. This package does not provide an uninstaller.

## Credential-free build

Use a clean checkout of the reviewed source, an arm64 Mac running macOS 27.2.1 build 26B131,
Xcode 27.2 build 27B52, the macOS 27.2 SDK build 26B118, Apple Swift 6.4.2 and Python 3.9 or later. Select the pinned Xcode with
`xcode-select` before running. Both the app and the extension are configured for version
`0.1.1`, build `2`.

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

The app bundle includes the unmodified GPLv3 text, the scoped public-source notices, the
original OpenSC LGPLv2.1 text and the exact project source revision, tree and URL.
The diagnostic carries the notices but omits the credential asset and its source excerpt.

## Prepare or rebuild the generation-2 resource

`make release-prepare` automatically downloads `src/libopensc/cwa-dnie.c` and
`COPYING` from the pinned OpenSC commit
`bc9a74a44565c091fc473d87193ec3a35c55b1f0`. It verifies their exact sizes and
SHA-256 hashes before using the data. Downloads require direct HTTPS access to
`raw.githubusercontent.com`; no GitHub account, token or OpenSC checkout is needed. The files stay in memory and are never executed or
cached in the repository. Download or integrity failures stop preparation.

### Download and prepare for a development build

From the repository root, run:

```sh
make prepare
```

This downloads DGP’s **1.6.8 ARM package** from its [official macOS download page](https://www.dnielectronico.es/PortalDNIe/PRF1_Cons02.action?pag=REF_1113),
verifies the package and library pins, and extracts the library with macOS `pkgutil`.
It downloads and verifies the OpenSC inputs, then creates
`Validation/private/SecureChannel/generation2.json` with mode `0600`. That file is
Git-ignored. No installer, middleware library or package script is executed.
Downloads and extracted files stay in private temporary storage and are removed
when preparation finishes or fails. No path edits, signing identity or administrator
privileges are needed for preparation.

A subsequent `make prepare` verifies and reuses an existing valid resource without
network access. An invalid resource or unsafe path stops the command and is never
silently replaced. A failed first preparation can be retried with the same command;
it starts with fresh temporary storage. If a download or checksum fails, check the
official download page rather than substituting another version or removing the checks.

Preparation requires macOS, Python 3.9 or later, Make, the macOS-provided `pkgutil`,
and direct HTTPS access to `www.dnielectronico.es` and `raw.githubusercontent.com`.
The reviewed DGP package is
[`libpkcs11-dnie-1.6.8_arm.pkg`](https://www.dnielectronico.es/descargas/software_MACOS/libpkcs11-dnie-1.6.8_arm.pkg),
2,825,440 bytes, SHA-256
`1eb6ef2117953ff787f8a6da6f26c2e9523ebcc2d91ad991c5350a8faab521ed`.
Its extracted ARM library must match the separate hash in the
[resource notice](../LICENSES/OpenSC-resource.md). This is data preparation; build
and installation remain separate `make build` and `make install` operations.

For fully offline setup, supply both pinned local inputs:

```sh
DNIERELEASE_OFFICIAL_BINARY="/canonical/path/to/extracted-arm64-library" \
DNIERELEASE_OPENSC_SOURCE="/canonical/path/to/cwa-dnie.c" make prepare
```

### Prepare a separate release input

Operators with an independently obtained library can prepare an external resource
instead. The supported input is the ARM64 PKCS#11 library from DGP macOS middleware
1.6.8, with the exact hash in the [resource notice](../LICENSES/OpenSC-resource.md).

```sh
credential_parent="$(mktemp -d /private/tmp/dnie-credential.XXXXXXXX)"
export DNIERELEASE_OFFICIAL_BINARY="/canonical/path/to/extracted-arm64-library"
export DNIERELEASE_FIXTURE="$credential_parent/generation2.json"
make release-prepare
```

Preparation verifies the DGP library hash, the presence of all 18 generation-2
fields in that library and their ordered manifest. It writes the deterministic
fixture format used by the runtime verifier. The local DGP library and any offline
source override must be owner-controlled, unlinked regular files with canonical
paths. The output must be absent under an existing owner-only directory with mode
`0700` outside the checkout. The completed file has mode `0600`. The macOS custody
checks reject ACL entries that could grant access on these files or their directory
ancestors. Only categorical results are printed. Keep all inputs and outputs out of Git.

### Offline preparation

To prepare without network access, additionally set
`DNIERELEASE_OPENSC_SOURCE=/canonical/path/to/cwa-dnie.c` to an already obtained,
verified copy of the same source. With that override, preparation makes no network
requests; the repository already contains the pinned upstream licence text. The
DGP library and all existing integrity/custody checks are still required.

The credential-bearing app carries the converted data source and Python transformer in
`Contents/Resources/OpenSC-source/`. Rebuild the exact resource from its corresponding
source using the released source checkout and an absent private output name. Copy the
excerpt from the app or the extracted package into a fresh user-owned directory first.

```sh
credential_parent="$(mktemp -d /private/tmp/dnie-rebuild.XXXXXXXX)"
(
  umask 077
  cat "/canonical/path/to/DNIeTokenHost.app/Contents/Resources/OpenSC-source/generation2.c" \
    > "$credential_parent/generation2.c"
)
export DNIERELEASE_EXCERPT="$credential_parent/generation2.c"
export DNIERELEASE_FIXTURE="$credential_parent/rebuilt-generation2.json"
make release-rebuild
```

The rebuild verifies the canonical source excerpt and its pinned field manifest.
It requires macOS, Python 3.9 or later and the excerpt, without access to the upstream
OpenSC file, the DGP binary, a private repository or an Xcode toolchain.
The full corresponding project source is identified by the bundle's `SOURCE.json`.

## Authorized Developer ID release

Create an independently reviewed authorization record outside the checkout before running
`make release`. The approval must cover the exact committed source, redistribution of the
exact credential input and its reproducible source excerpt, and transfer of both to Apple
in the notarization package. The corresponding project source must be available to recipients
at the recorded source location before binary distribution.
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
  "version": "0.1.1",
  "build": "2",
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
authorized unsigned payloads must agree before any signing. Each package check also verifies
the exact transformer and regenerates the approved fixture from its packaged source excerpt.
The existing staging script and the runtime fixture verifier both validate the staged input. The canonical
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


For binary download distribution, provide equivalent access at no extra charge to the exact
complete Corresponding Source for as long as the binary is offered. Put it at the binary
download location or place clear directions beside that download to the project-controlled
source location. Include the exact project build/packaging scripts and the editable 18-field
resource source with its conversion procedure. A URL/hash or approval assertion alone does
not establish that the source is actually available. The source excerpt supplied inside the
package must also be included in that approved source delivery; no values need enter public
Git. Verify source access before approving publication of any binary. "Limited" or
"restricted-scope" here describes selecting the 18 fields, never additional restrictions on
recipients' GPL rights.


## Development installation authorization and diagnostics

Run `make install` as your normal user. The workflow selects its authorization
method once. A controlling Terminal uses `sudo` and its normal policy-managed
authorization ticket across installation phases. Password prompts can recur if
that policy or ticket expiry requires them. Without a controlling terminal, the
existing native administrator dialogs require the active console user; separate
privileged phases can still request separate authorization. No password is
collected or stored by DNIe Bridge.

`make card-info` builds a small standalone diagnostic with an ad-hoc smart-card
entitlement; it needs Xcode but no terminal-data fixture or Apple signing identity.
It reports CTK reader-slot/card snapshots and separately observes native key
references matching fixed DNIe role labels in the Data Protection keychain,
with interaction disabled and no legacy-keychain fallback. It never
opens a smart-card session, sends an APDU, requests a PIN or signs data. It does
not establish ownership of a particular inserted card or prove authentication.
No reader names, ATRs, holder data, token IDs or key material are printed. Exit0
means the observation completed, including no-reader/no-card results; errors or
indeterminate observations return nonzero. Temporary build output is private
and disposed after the command; offline tests are included in `make check`.
