# Security guidance

This source implements a native smart-card identity provider. A DNIe is a real identity card: use only a card and reader you are authorized to operate. Keep terminal credential fixtures and local-development apps private. Never commit credential values or generated credential source. Any distribution or upload of the separately attributed release resource, its editable source and a containing app requires exact release approval covering disclosure and the destination, including Apple notarization transfer. See the release workflow and scoped resource notices.

Enter the known-correct DNIe PIN only in the native macOS authentication prompt. Never place a PIN in a command, file, fixture, screenshot, or log. Do not deliberately try a wrong PIN. Stop card operations after an unexplained response, retry indication, or state change, and diagnose offline before another attempt. Do not send administrative or undocumented state-changing commands to the card.

`make build` verifies a local fixture and signs an Apple Development app for local testing. `make install` and `make uninstall` operate on an exact inspected artifact and can request administrator authorization. A failed or interrupted transaction needs state review before retry. The pilot installer does not alter certificate trust or browser configuration. Do not bypass TLS errors to make a service work.

The source snapshot does not establish public release readiness. Report suspected security defects without including a PIN, private key, credential bytes, personal certificate contents, or raw card traces.
