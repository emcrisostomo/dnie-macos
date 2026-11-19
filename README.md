# DNIe Bridge

Source for an experimental native macOS CryptoTokenKit provider for the Spanish DNIe. It uses macOS Security.framework, CryptoTokenKit, TKSmartCard, and a supported reader. The source is available for review and authorized local development. No credential asset or distributable app is included.

## Status and scope

The native provider and a manual Make build/install/uninstall workflow have been validated in the private project environment. The release tooling passed two-build repeatability and package integrity checks with an independently authorized local fixture on the pinned environment, using runtime sources at `87fe63f0b9e48fdd8459df12353710fb94fce2de`. This was an unsigned local test, with no installation, card use or Apple upload. That evidence does not establish support for other Macs, readers, cards, sites, or signing identities. Developer ID distribution, notarization, clean-machine lifecycle, and release authorization remain open. Automatic updates are unsupported.

The app icon has been omitted because its publication rights have not been established. An unbranded app can be built from this source.

## Local development requirements

- Apple silicon Mac, current macOS and full Xcode selected for command-line tools; `jq` and the macOS supplied Make.
- A valid Apple Development signing identity for local builds. Never publish its hash or private key.
- A generation-2 terminal credential fixture that you have independently obtained and are authorized to use locally. This repository provides no credential bytes. The [release workflow](Release/README.md) documents deterministic preparation from hash-pinned OpenSC and official DGP inputs that you separately obtain and are authorized to use. The fixture must match the metadata and source digest checked by [`stage-production-credential-asset.sh`](Validation/Scripts/stage-production-credential-asset.sh). Place it at `Validation/private/SecureChannel/generation2.json`, as a regular, non-symlink file owned by your user with mode `0600`. The build fails closed if it is absent or fails the guard. Keep local-development fixtures and builds private. An explicitly approved release uses the attributed resource model below.

The local development build (`make build`) needs the fixture. Offline checks, tests and unsigned release diagnostics can run without it.

## Manual workflow

From this repository root, run Make as your normal user:

```sh
make help
make check
make test
make build
make install
make status
make uninstall
```

`make build` signs a private Apple Development app under `DerivedData/T067/Build/Products/Release/`. You may select among multiple valid local development identities by setting `DNIE_SIGNING_IDENTITY_SHA1=<40-hex-hash>` for the build; do not store the value in this repository. `make install` and `make uninstall` can request separate macOS administrator authorizations. These prompts ask for a Mac administrator password, never the DNIe PIN. `make status` inspects the exact installed path and registration. The workflow refuses ambiguous ownership and registration states. `make upgrade`, `make disable`, `make enable`, and `make clean` are unsupported and refuse.

Do not run `sudo make`, export or distribute a credential-bearing app, or treat an Apple Development build as release ready. The build and lifecycle scripts use exact targets and checks; if a transaction stops, diagnose its state before retrying. Transaction archives can contain signed credential-bearing apps and must stay private.

For card use, select the DNIe Authentication identity from the native macOS certificate prompt in Safari or another compatible native client. Enter a known-correct PIN only in the native system prompt. Never deliberately test a wrong PIN or retry after an unexplained card response. Certificate-chain trust is separate from token installation; this workflow does not alter trust settings.

## Tests

`make check` runs shell syntax and offline workflow, lifecycle, and safety fixtures. `make test` runs the same workflow fixtures. For core Swift tests, run `swift test --package-path Packages/DNIeCore` with an appropriate installed SDK. Tests whose required guide-derived fixtures could not be cleared for this source snapshot are omitted. The Xcode project retains the other extension tests. Neither test target proves physical-card behavior.

## Licensing and provenance

Original code and documentation in this snapshot are offered under GPL-3.0-or-later to the extent the relevant rights holders can make that grant. See [LICENSE](LICENSE) and [the scoped notices](LICENSES/README.md). The local credential fixture is excluded from the project-original grant. The selected release resource copy uses GPL-3.0-or-later through upstream LGPL2.1 section 3, preserving OpenSC attribution, provenance and dated changes. The package accompanies it with editable restricted-scope source and conversion instructions; upstream OpenSC remains LGPL-2.1-or-later. See [resource notices](LICENSES/OpenSC-resource.md). This repository contains no credential values. Exact release and Apple-transfer approvals remain separate. [Security guidance](SECURITY.md) covers sensitive operations.

## Release packaging

Use an Apple silicon Mac running macOS 27.2.1 (26B131), with Xcode 27.2 (27B52), the macOS 27.2 SDK (26B118) and Swift 6.4.2. The app targets macOS 26.0 or later. Packaging starts from an exact, clean public commit. Use an output directory outside the checkout.

```sh
make release-help
make release-test
make release-check DNIERELEASE_REVISION="$(git rev-parse HEAD)"
make release-repeatability DNIERELEASE_REVISION="$(git rev-parse HEAD)" \
  DNIERELEASE_OUTPUT=/private/tmp/dnie-release-repeatability
```

To prepare a credential input, separately obtain the exact authorized OpenSC source and official
DGP binary described in [the resource notices](LICENSES/OpenSC-resource.md). Use an existing
owner-only directory outside the checkout and an absent output file:

```sh
DNIERELEASE_OPENSC_SOURCE=/canonical/private/cwa-dnie.c \
DNIERELEASE_OFFICIAL_BINARY=/canonical/private/official-library \
DNIERELEASE_FIXTURE=/canonical/private/generation2.json make release-prepare
```

The command checks both pinned hashes and every selected field before writing a mode-0600
fixture. No credential is downloaded or printed. The authorized release also includes the
editable limited data source and its conversion code; `make release-rebuild` reconstructs the
fixture from that source using the documented `DNIERELEASE_EXCERPT` and `DNIERELEASE_FIXTURE`
inputs. Preparation does not approve redistribution, signing or Apple transfer.

Choose an absent output directory for a new run. The default unsigned build is a credential-free diagnostic. The repeatability check compares the unsigned app payload inventories from two independent builds. The diagnostic cannot be used for DNIe authentication.

The current local-development permission grants neither credential redistribution nor Apple upload. The owner-selected OpenSC-derived release-copy route is documented in the resource notices; it does not make a local build an approved release. `make release` requires separate explicit source and credential redistribution authorization for the requested release, an authorized fixture, matching Developer ID Application and Installer identities, and an explicit notarization Keychain profile. See the [release workflow](Release/README.md) for input parameters, verification and interrupted notarization recovery.

The flat package delivers the app to `/Applications/DNIeTokenHost.app`. Registration, activation, clean-machine operation and removal require separate validation. The manual `make uninstall` command applies to the manual development workflow and its recorded installation state.
