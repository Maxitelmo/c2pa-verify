# Measured SDK behavior

Checked against c2pa-python 0.38.0 (c2pa-rs 0.91.0). It must be checked again when
upgrading: `tests/test_sdk.py` runs against the real SDK.

## Configuration

- It goes in `Context.from_dict(...)`. Unknown keys are **silently ignored**.
- Without `trust.trust_config`, c2pa-rs accepts only the emailProtection, timeStamping
  and OCSPSigning EKUs. documentSigning, MS C2PA signing and c2pa-kp-claimSigning give
  `signingCredential.invalid` ("missing required EKU"), with a correct hash and
  signature. The Builder has the same gap when signing.

## Trust lists

- `trust_kind: "tsa"` **does not isolate**: a CA loaded only as a TSA gives "Trusted"
  to a manifest signer. That is why `TRUSTED` requires `trustListUri` to be the signers
  list.
- With certificates present in both lists, `trustListUri` alternates between runs (not
  deterministic). That is why the TSA list goes in without the certificates it shares
  with the signers list.
- Without anchors, an unknown signer gives `validation_state: "Valid"` with
  `signingCredential.untrusted` among the failures. `verify_trust=false` also gives
  "Valid".

## Validity

- The signer's validity is evaluated at the time of the time-stamp **only if the TSA
  is anchored** (`timeStamp.trusted`); otherwise, at read time. A signature with a valid
  time-stamp from an unknown TSA expires just like one with no time-stamp.

## Network

- `core.allowed_network_hosts: []` blocks the SDK's HTTP requests even if another key
  enables them.
- That list does not reach CAWG identities (c2pa-rs#1645), so
  `decode_identity_assertions` is set to `False`. The synchronous FFI reader does not
  resolve them today either.

## Errors

| Situation | What the SDK returns |
|---|---|
| No manifest | `ManifestNotFound` |
| Broken file | `Other` |
| Remote manifest | Base `C2paError` with `Remote: must fetch remote manifests from url <URL>`, not the `RemoteManifest` subclass |
| Format not read | `NotSupported` (BMP, for example) |

## Loading the native library

c2pa-python looks for `c2pa_c` first in the working directory, in `libs/` and in
`artifacts/` (and their platform subfolders), and only then in its package. A library
left there would run inside the process, so `c2pa` is not imported if one is found.
