# trust/: C2PA trust lists

X.509 anchors the verifier uses to tell a **valid** manifest (intact, unknown signer)
from a **trusted** one (intact, with the signer on the C2PA trust list). Without these
lists the SDK can never return "Trusted" (C2PA 2.2 §14.4).

They are public certificates only, with no private keys.

## Offline operation

The verifier **downloads nothing when reading**: not these lists, not OCSP, not remote
manifests. The lists are updated by publishing a new version (see below). A list whose
SHA-256 does not match the one pinned in `listas.py` is not loaded, and then no signer
is reported as trusted.

## Source

- Official repository: https://github.com/c2pa-org/conformance-public
  (`trust-list/` folder), maintained by C2PA Conformance.
- Commit: `d6dec63476e2636095d1291d24b29ffa2d4e1ac0` (2026-10-26, "Automated Sync:
  Update trust lists").
- Integrity when downloaded: the git blob SHA-1 of each file matches the commit's tree
  (checked on 2026-11-03).
- License: **Creative Commons Attribution 4.0 International (CC BY 4.0)**, text in
  `LICENSE-C2PA-TRUST-LIST.txt`. Redistributed unchanged.

| File | Content | Certificates | SHA-256 |
|---|---|---|---|
| `C2PA-TRUST-LIST.pem` | Anchors of manifest signers | 32 | `b3949271a07b007e92ef1d18050b55388f5e0d2686a16fd864176c48421af8ae` |
| `C2PA-TSA-TRUST-LIST.pem` | Anchors of time-stamp authorities (RFC 3161) | 23 | `7182cb227c02701be0eebd67ab635fca7f85431c32796fb53b267c657cd2c675` |

The C2PA *Interim Trust List* was frozen on 2026-01-01; these are the current lists of
the conformance program.

## How to update

1. Download both `.pem` files from `trust-list/` at a specific commit of the official
   repository (not an unpinned `main`) and check the git blob SHA-1 against that
   commit's tree.
2. Replace the files here (the repository's `.gitattributes` keeps them in LF).
3. Update `SHA256_FIJADO` in `listas.py` and the table in both READMEs.
4. Run the suite (`tests/test_listas.py` checks file against pinned hash).

## Checked SDK behavior (c2pa-python 0.38.0, c2pa-rs 0.91.0)

- The `tsa` list kind does not isolate: a CA loaded only as a TSA still validates the
  manifest signer. That is why the verifier only accepts "trusted" when the SDK reports
  having validated against `C2PA-TRUST-LIST.pem#sha256=<hash>`.
- Some certificates are in both lists (Google, SSL.com). With both lists whole, the SDK
  reported one or the other as `trustListUri` depending on the run (not deterministic).
- The SDK evaluates the signer's validity at the time of the time-stamp only if it comes
  from an anchored TSA (`timeStamp.trusted`); otherwise at read time, and a signature with
  a valid time-stamp expires just like one without.
- That is why the TSA list goes into the SDK **without the certificates it shares with
  the signers list**. In this version: 7 of its 23 certificates, and the result states it
  in `trust_lists`. Without the signers list, the TSA list is not loaded.
- An unknown configuration key is ignored with no error: building the configuration has
  tests against the real SDK.
