# c2pa-verify

**Offline, deterministic** verification of C2PA manifests, built for forensic work.
It reports the state of the signature and what the manifest declares, with the
traceability needed to reproduce the result.

> **[Versión en español](https://github.com/Maxitelmo/c2pa-verify/blob/main/README.es.md)**

## What it does not do

- It does not say whether the content is true. A trusted signature tells you who
  signed and that the file has not changed since.
- It does not detect AI. It reports what the manifest **declares**; it does not
  analyze pixels and does not score anything.
- `ABSENT` rules nothing out: most files have no manifest, and messaging platforms
  usually remove it.

## When to use another tool

[c2pareader](https://github.com/abrignoni/c2pareader) (MIT) reads what a file
declares, in pure Python with no dependencies, but it does not verify signatures.
This package takes the next step, verification, at the cost of depending on
c2pa-python and its native library. They are complementary: one reads quickly
anywhere, the other tells you whether what is declared is backed by a signature.

## Install and use

Requires Python 3.10 or later.

```bash
pip install c2pa-verify
```

```bash
c2pa-verify --lang en photo.jpg video.mp4
```

```bash
c2pa-verify --lang en --json photo.jpg
```

```python
from c2pa_verify import verify

r = verify("photo.jpg")
print(r["state"], r["label"], r["signer"])
```

**The default language of the command is Spanish**, so pass `--lang en`. The language
is always chosen explicitly and never taken from the machine's settings: the same
file gives the same output on any computer. In Python, `verify()` returns English and
`verificar()` returns Spanish. Both run the same verification. Code comments are in
Spanish for now.

## States

| State | Meaning |
|---|---|
| `TRUSTED` | Manifest intact, and signer validated against the C2PA signers list |
| `VALID_UNTRUSTED` | Manifest intact, but the signer is not on the loaded trust list |
| `INVALID` + `invalidity: "credential"` | Content intact, but the certificate is unsuitable, expired or revoked |
| `INVALID` + `invalidity: "integrity"` | The content does not match what was signed, or the signature does not verify |
| `MALFORMED` | There is a manifest, but it cannot be read |
| `REMOTE` | The file points to a manifest on the internet, which is **not downloaded** (doing so would alert whoever controls that address) |
| `ABSENT` | There is no manifest |
| `None` | Could not be determined; see `reason`. It does not mean there is no manifest |

**`VALID_UNTRUSTED` does not mean the signature is fake.** The signature verifies and
the content is the one signed. It only means the signer is not on the list loaded in
this version, so its identity is not vouched for by that list.

SDK validation codes such as `assertion.dataHash.mismatch` are C2PA standard names
and are not translated.

## Guarantees

- **No network:** no OCSP, no remote manifests, and an empty list of allowed hosts.
  The tests check this with a local listener and a positive control.
- **No writes:** the file is only read.
- **Pinned lists:** a list whose SHA-256 does not match the pinned one is not loaded,
  and then nobody comes out as trusted.
- **Attributable trust:** `TRUSTED` requires that the SDK validated against the
  signers list, not the time-stamp list.
- **Traceable:** each result records the file's SHA-256, the read date, versions, the
  hash of the lists and the accepted EKUs.

## The result depends on the date

A signature without a time-stamp from an anchored TSA is validated against the read
date: once the certificate expires, the same file becomes `INVALID` by credential.
Always record `read_at_utc` with the result.

## Known limitations

- The SDK runs inside the process: a file that makes the native library fail can
  close the program. For untrusted batches, isolate it in a child process.
- A foreign native library in the working directory is detected and not loaded, but
  the hash of the library actually loaded is not verified.
- CAWG identities are neither decoded nor resolved.
- The install is heavy: the `c2pa` package from c2pa-python takes about 300 MB on
  Windows.
- Lists age: an installation keeps the lists of its version until updated. A weekly
  job opens an issue in this repository when the source changes, but updating them
  takes a review and a new release (see
  [trust/README.en.md](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/trust/README.en.md)).
  To see which lists were used, check `trust_lists` in the result.

See also [docs/SDK-FINDINGS.md](https://github.com/Maxitelmo/c2pa-verify/blob/main/docs/SDK-FINDINGS.md).

## How to verify the method

The method is meant to be reviewed and reproduced by anyone.

1. **Read the rules:** states come from `_estado_c2pa`, `_tipo_invalidez` and
   `_extraer_info_c2pa`, in
   [verificador.py](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/verificador.py).
   The SDK configuration is in `settings_c2pa`, in
   [listas.py](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/listas.py).
   The English output is produced from that same result in
   [english.py](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/english.py).
2. **Run the tests:**

   ```bash
   git clone https://github.com/Maxitelmo/c2pa-verify.git
   ```

   ```bash
   cd c2pa-verify
   ```

   ```bash
   pip install -e .[dev]
   ```

   ```bash
   python -m pytest
   ```

   They sign their own files with a throwaway CA and TSA, against the real SDK, and
   cover each state.
3. **Check the lists:** the SHA-256 of each list must match the original file in
   [conformance-public](https://github.com/c2pa-org/conformance-public) at the commit
   given in
   [trust/README.en.md](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/trust/README.en.md).
4. **Compare results:** what is declared can be compared with c2pareader or c2patool.
   The signature state is only comparable if the other tool loads the same lists and
   accepts the same EKUs.

**Limit of the validation:** the repository contains no real images. It was also
measured on a private set of 54 files, not published because it includes third-party
material, so that measurement cannot be reproduced from here. The tests can.

If you find a wrong result, please open an issue. **Do not upload evidence or files
from a case:** the codes from `--json` are enough, without identifying data, or a test
file of your own.

## License

Apache-2.0 (see [LICENSE](https://github.com/Maxitelmo/c2pa-verify/blob/main/LICENSE)
and [NOTICE](https://github.com/Maxitelmo/c2pa-verify/blob/main/NOTICE)). The trust
lists are from C2PA Conformance, under CC BY 4.0.
