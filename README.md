# DNIe Bridge

Source for an experimental native macOS CryptoTokenKit provider for the Spanish DNIe. It uses macOS Security.framework, CryptoTokenKit, TKSmartCard, and a supported reader. The source is available for review and authorized local development. No credential asset or distributable app is included.

## Status and scope

The native provider and a manual Make build/install/uninstall workflow have been validated in the private project environment. This source snapshot has not yet been validated as a credential-bearing build. That evidence does not establish support for other Macs, readers, cards, sites, or signing identities. Developer ID distribution, notarization, clean-machine lifecycle, and release authorization remain open. Automatic updates are unsupported.

The app icon has been omitted because its publication rights have not been established. An unbranded app can be built from this source.

## Local development requirements

- Apple silicon Mac, current macOS and full Xcode selected for command-line tools; `jq` and the macOS supplied Make.
- A valid Apple Development signing identity for local builds. Never publish its hash or private key.
- A generation-2 terminal credential fixture that you have independently obtained and are authorized to use locally. This repository provides no credential bytes, download, or extraction procedure. The fixture must match the metadata and source digest checked by [`stage-production-credential-asset.sh`](Validation/Scripts/stage-production-credential-asset.sh). Place it at `Validation/private/SecureChannel/generation2.json`, as a regular, non-symlink file owned by your user with mode `0600`. The build fails closed if it is absent or fails the guard. Keep this fixture and all built apps private.

The fixture is needed only for `make build`. `make check` and `make test` run offline without it.

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

Original code and documentation in this snapshot are offered under GPL-3.0-or-later to the extent the relevant rights holders can make that grant. See [LICENSE](LICENSE) and [the scoped notices](LICENSES/README.md). The local credential fixture and credential-bearing builds are excluded from this grant and from redistribution authorization. [Security guidance](SECURITY.md) covers sensitive operations.
