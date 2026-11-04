# -*- coding: utf-8 -*-
"""English presentation of a verification result.

There is one method: verify() runs verificador.verificar() and translates its
result at the end, so both languages always come from the same verification.
SDK validation codes are C2PA standard names and are never translated. Text that
comes from the SDK or the operating system is passed through as it is.
"""

import re

from . import verificador as _v

STATES = {
    _v.C2PA_CONFIABLE: "TRUSTED",
    _v.C2PA_VALIDO_NO_CONFIABLE: "VALID_UNTRUSTED",
    _v.C2PA_INVALIDO: "INVALID",
    _v.C2PA_MALFORMADO: "MALFORMED",
    _v.C2PA_REMOTO: "REMOTE",
    _v.C2PA_AUSENTE: "ABSENT",
    None: None,
}
INVALIDITY = {_v.C2PA_INVALIDEZ_CREDENCIAL: "credential", _v.C2PA_INVALIDEZ_INTEGRIDAD: "integrity", None: None}
TYPES = {"generacion": "generation", "edicion_ia": "ai_edit", "captura": "capture",
         "algoritmico": "algorithmic", "informativo": "informational", None: None}

_KEYS = {
    "archivo": "file", "sha256": "sha256", "fecha_lectura_utc": "read_at_utc", "version": "version",
    "c2pa_python": "c2pa_python", "sdk_disponible": "sdk_available", "estado": "state",
    "etiqueta": "label", "invalidez": "invalidity", "hallazgos": "findings", "codigos": "codes",
    "firmante": "signer", "generador": "generator", "digital_source_type": "digital_source_type",
    "tipo": "type", "ingredientes_ia": "ai_ingredients", "asistente_ia": "ai_assistant",
    "validation_state": "validation_state", "trust_list_uri": "trust_list_uri",
    "confianza_no_atribuible": "unattributable_trust", "url_remota": "remote_url",
    "listas_confianza": "trust_lists", "eku_aceptados": "accepted_ekus", "motivo": "reason",
}

_LABELS = {
    _v.C2PA_CONFIABLE: "valid, signer on the C2PA trust list (manifest intact)",
    _v.C2PA_VALIDO_NO_CONFIABLE: "valid, signer not on the loaded trust list (manifest intact)",
    _v.C2PA_INVALIDO: "invalid (the content does not match what was signed, or the signature does not verify)",
    _v.C2PA_MALFORMADO: "not verifiable (manifest present but unreadable)",
    _v.C2PA_REMOTO: "not verified (manifest at a remote address that is not downloaded)",
}
_LABEL_CREDENTIAL = "not accepted: signer's certificate is not valid (content intact)"

_HASH_MISMATCH = ("the file content does not match what was signed (it changed after signing, "
                  "or the manifest belongs to other content)")
FAILURES = {
    "assertion.dataHash.mismatch": _HASH_MISMATCH,
    "assertion.bmffHash.mismatch": _HASH_MISMATCH,
    "assertion.boxesHash.mismatch": _HASH_MISMATCH,
    "assertion.collectionHash.mismatch": "the content does not match the signed hash of the collection",
    "assertion.hashedURI.mismatch": "a manifest assertion does not match the one that was signed",
    "claimSignature.mismatch": "the manifest signature does not verify",
    "signingCredential.revoked": "the signer's certificate is reported as revoked",
    "signingCredential.ocsp.revoked": "the signer's certificate is reported as revoked",
    "signingCredential.expired": "the signer's certificate had expired",
    "signingCredential.invalid": "the signer's certificate is not suitable for signing manifests",
}
_FAILURE_DEFAULT = "manifest validation failure"
_FINDING_MALFORMED_ES = "C2PA manifiesto malformado: no se pudo leer ni validar"
_FINDING_MALFORMED = "C2PA malformed manifest: could not be read or validated"
_RE_FINDING = re.compile(r"^C2PA (\S+): ")

# Exact Spanish reasons. Anything else comes from the SDK or the system.
REASONS = {
    "c2pa-python no está disponible": "c2pa-python is not available",
    "formato que el SDK no lee": "format the SDK does not read",
    "archivo no encontrado": "file not found",
    "el SHA-256 no coincide con el fijado (lista alterada o de otra versión)":
        "the SHA-256 does not match the pinned one (altered list, or from another version)",
    "el archivo no es un PEM": "the file is not a PEM",
    "sin la lista de firmantes no se carga": "not loaded without the signers list",
    "todos sus certificados están en la lista de firmantes": "all its certificates are in the signers list",
    "el SDK no aceptó la configuración": "the SDK did not accept the configuration",
}
_REASON_PREFIXES = (
    ("no se pudo leer el archivo: ", "could not read the file: "),
    ("no se pudo leer: ", "could not read: "),
    ("JSON del manifiesto ilegible: ", "unreadable manifest JSON: "),
)
_RE_FOREIGN_LIBRARY = re.compile(r"^biblioteca nativa ajena en la carpeta de trabajo \((.*)\): no se cargó$", re.S)
_UNATTRIBUTABLE_ES = "lista no informada por el SDK"
_ASSISTANTS = {"com.anthropic.claude.provided": "Claude, by Anthropic"}


def _reason(text):
    if not text:
        return text
    if text in REASONS:
        return REASONS[text]
    for spanish, english in _REASON_PREFIXES:
        if text.startswith(spanish):
            return english + text[len(spanish):]
    library = _RE_FOREIGN_LIBRARY.match(text)
    if library:
        return f"foreign native library in the working directory ({library.group(1)}): not loaded"
    return text


def _finding(text):
    if text == _FINDING_MALFORMED_ES:
        return _FINDING_MALFORMED
    code = _RE_FINDING.match(text)
    return f"C2PA {code.group(1)}: {FAILURES.get(code.group(1), _FAILURE_DEFAULT)}" if code else text


def _label(state, invalidity):
    if state == _v.C2PA_INVALIDO and invalidity == _v.C2PA_INVALIDEZ_CREDENCIAL:
        return _LABEL_CREDENTIAL
    return _LABELS.get(state)


def _ingredient(i):
    return {
        "manifest": i["manifiesto"], "signer": i["firmante"], "digital_source_type": i["digital_source_type"],
        "type": TYPES[i["tipo"]], "title": i["titulo"], "relationship": i["relacion"],
        "state": STATES[i["estado_c2pa"]], "invalidity": INVALIDITY[i["invalidez"]], "depth": i["profundidad"],
    }


def _assistant(a):
    return {"name": _ASSISTANTS.get(a["accion"], a["nombre"]), "action": a["accion"],
            "origin_confidence": a["confianza_origen"]} if a else None


def _trust_list(t):
    return {"sha256": t["sha256"], "verified": t["verificada"], "loaded": t["cargada"],
            "reason": _reason(t["motivo"]), "certificates": t["certificados"],
            "certificates_in_sdk": t["certificados_en_sdk"]}


def to_english(result: dict) -> dict:
    """The result of verificar() in English. An unmapped key or state raises
    KeyError on purpose: a wrong translation must not pass unnoticed."""
    out = {_KEYS[key]: value for key, value in result.items()}
    out["state"] = STATES[result["estado"]]
    out["invalidity"] = INVALIDITY[result["invalidez"]]
    out["type"] = TYPES[result["tipo"]]
    out["label"] = _label(result["estado"], result["invalidez"])
    out["findings"] = [_finding(f) for f in result["hallazgos"]]
    out["ai_ingredients"] = [_ingredient(i) for i in result["ingredientes_ia"]]
    out["ai_assistant"] = _assistant(result["asistente_ia"])
    out["reason"] = _reason(result["motivo"])
    if result["confianza_no_atribuible"] == _UNATTRIBUTABLE_ES:
        out["unattributable_trust"] = "list not reported by the SDK"
    if result["listas_confianza"] is not None:
        out["trust_lists"] = {name: _trust_list(t) for name, t in result["listas_confianza"].items()}
    return out


def verify(path) -> dict:
    """Verify the C2PA manifest of a file, offline and without modifying it.

    state is TRUSTED, VALID_UNTRUSTED, INVALID, MALFORMED, REMOTE or ABSENT, or
    None if it could not be determined (see reason; None does NOT mean there is
    no manifest). signer, generator, digital_source_type, type, ai_ingredients and
    ai_assistant are what the manifest DECLARES. read_at_utc matters: a signature
    without a trusted time-stamp expires with its certificate.
    """
    return to_english(_v.verificar(path))
