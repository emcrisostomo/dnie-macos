# OpenSC generation-2 credential resource

The credential-bearing release includes the generation-2 terminal credential data from
OpenSC's `src/libopensc/cwa-dnie.c` at commit
`bc9a74a44565c091fc473d87193ec3a35c55b1f0`. The upstream file identifies
Copyright (C) 2010 Juan Antonio Martinez and carries a GNU LGPL v2.1-or-later grant.
[Pinned OpenSC source](https://github.com/OpenSC/OpenSC/blob/bc9a74a44565c091fc473d87193ec3a35c55b1f0/src/libopensc/cwa-dnie.c)

On 2026-11-19, the dnie-macos project selected the 18 generation-2 declarations, normalized
their formatting and omitted the other OpenSC code and data. The corresponding source
excerpt identifies these changes. Under section 3 of LGPL v2.1, this extracted copy uses
the GNU GPL version 3 or any later version. That election applies to the excerpt and its
derived credential resource. The upstream source keeps its original licence.
The bundle includes the full [GPLv3 text](../LICENSE) and the
[unmodified upstream LGPLv2.1 text](OpenSC-LGPL-2.1.txt) for provenance.

| Input or check | SHA-256 |
| --- | --- |
| OpenSC `src/libopensc/cwa-dnie.c` | `6528a9662523362f53479440c6611a241cda1940a2b5a05fa5deb4c8bf3cba4a` |
| PKCS#11 library from DGP macOS ARM middleware 1.6.8 | `d2de4308190433a22683ef7fa85637b446f2a9420e35e50b86314a5590c46bc2` |
| Ordered generation-2 field manifest v2 | `3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d` |
| Verbatim OpenSC `COPYING` at the same commit, 26,522 bytes | `376b54d4c5f4aa99421823fa4da93e3ab73096fce2400e89858632aa7da24a14` |

The original DGP binary served as an independent byte-equivalence check during preparation.
The release copy draws on the generation-2 data contributed to OpenSC by rickyepoderi.
The package excludes the DGP binary and OpenSC executable code. [OpenSC pull request #2109](https://github.com/OpenSC/OpenSC/pull/2109)

The app's `Contents/Resources/OpenSC-source/` contains the editable `generation2.c`
data excerpt and `credential_format.py`, which converts the 18 declarations into the JSON
fixture. The converter preserves the field names and byte values, encodes the two terminal
RSA tuples in PKCS#1 and writes deterministically ordered JSON. To regenerate the shipped
fixture, use `make release-rebuild` in the exact source revision identified by the app's
`Contents/Resources/SOURCE.json`. The Python transformer exposes `extract_fields` and
`encode_fixture` for editing and rebuilding another copy. The release workflow accepts only
the reviewed generation-2 manifest. See the source checkout's `Release/README.md` for the
offline preparation and rebuilding commands and exact input requirements.

A release requires separate authorization covering source rights, redistribution of the
exact credential and source excerpt, and transfer of both to Apple for notarization.
Before binary distribution, make the complete corresponding project source available
at the project-controlled source location recorded in `SOURCE.json`. The upstream
OpenSC link documents provenance.


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
