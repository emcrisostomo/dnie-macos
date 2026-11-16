# Local credential assets

This directory is the ADR-008 local-only resource boundary. The tracked repository intentionally
contains no terminal credential bytes.

Run `Validation/Scripts/stage-production-credential-asset.sh` after the already authorized local
generation-2 fixture has been prepared. It writes an ignored mode-`0600` `generation2.json` here.
`CredentialAssetStore` rechecks the recorded source/distribution provenance, manifest-v2 digest,
exact field set, and both derived terminal private-key bindings before returning the asset.

Publishing either the generated JSON or a build containing it is distribution and remains
deferred by ADR-008.
