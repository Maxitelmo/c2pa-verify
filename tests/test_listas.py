# -*- coding: utf-8 -*-
"""Listas de confianza C2PA: archivos, hash fijado y configuración offline.
No requiere c2pa-python."""

import hashlib
import os

import pytest

from c2pa_verify import verificador as det
from c2pa_verify import listas as conf

RAIZ = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "c2pa_verify")


@pytest.mark.parametrize("nombre", [conf.FIRMANTES, conf.TSA])
def test_listas_del_repo_coinciden_con_el_hash_fijado(nombre):
    ruta = os.path.join(RAIZ, conf.SUBDIR, nombre)
    with open(ruta, "rb") as f:
        datos = f.read()
    # LF como las publica C2PA (.gitattributes -text): con CRLF cambia el hash.
    assert b"\r\n" not in datos
    assert hashlib.sha256(datos).hexdigest() == conf.SHA256_FIJADO[nombre]
    assert datos.count(b"-----BEGIN CERTIFICATE-----") > 0
    assert b"PRIVATE KEY" not in datos


def test_cargar_listas_del_paquete():
    listas = conf.cargar_listas()
    for nombre in (conf.FIRMANTES, conf.TSA):
        assert listas[nombre]["verificada"] is True
        assert listas[nombre]["sha256"] == conf.SHA256_FIJADO[nombre]
    assert listas[conf.FIRMANTES]["cargada"] is True
    # De la TSA van al SDK solo los certificados que no están en la de firmantes.
    assert listas[conf.TSA]["cargada"] is True


def _certificados(pem: str) -> set:
    """DER (base64 sin espacios) de cada certificado de un PEM."""
    import re
    return {re.sub(r"\s", "", b) for b in re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)}


def test_lista_tsa_entra_sin_los_certificados_de_la_de_firmantes():
    # Con un certificado en las dos anclas, el trustListUri del SDK alternaba entre
    # ejecuciones. Sin repetidos, cada uno tiene un solo origen.
    listas = conf.cargar_listas()
    with open(listas[conf.FIRMANTES]["ruta"], encoding="ascii") as f:
        firmantes = _certificados(f.read())
    with open(listas[conf.TSA]["ruta"], encoding="ascii") as f:
        tsa = _certificados(f.read())
    en_sdk = _certificados(listas[conf.TSA]["pem"])
    assert en_sdk == tsa - firmantes and en_sdk
    assert (listas[conf.TSA]["certificados_en_sdk"], listas[conf.TSA]["certificados"]) == (len(en_sdk), len(tsa))
    assert listas[conf.FIRMANTES]["certificados_en_sdk"] == listas[conf.FIRMANTES]["certificados"] == len(firmantes)


def test_lista_tsa_contenida_en_la_de_firmantes_no_agrega_ancla(tmp_path, monkeypatch):
    listas = conf.cargar_listas()
    with open(listas[conf.FIRMANTES]["ruta"], "rb") as f:
        pem = f.read()
    for nombre in (conf.FIRMANTES, conf.TSA):
        (tmp_path / nombre).write_bytes(pem)
    monkeypatch.setattr(conf, "_dirs_trust", lambda: [str(tmp_path)])
    monkeypatch.setitem(conf.SHA256_FIJADO, conf.TSA, conf.SHA256_FIJADO[conf.FIRMANTES])
    info = conf.cargar_listas()[conf.TSA]
    assert info["verificada"] is True and info["cargada"] is False
    assert "todos sus certificados están en la lista de firmantes" in info["motivo"]


@pytest.fixture
def kit_trust(tmp_path, monkeypatch):
    monkeypatch.setattr(conf, "_dirs_trust", lambda: [str(tmp_path)])
    return tmp_path


def test_lista_alterada_no_se_carga(kit_trust):
    (kit_trust / conf.FIRMANTES).write_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n")
    info = conf.cargar_listas()[conf.FIRMANTES]
    assert info["cargada"] is False
    assert info["pem"] is None
    assert "no coincide" in info["motivo"]
    assert info["sha256"]  # se registra el hash real igual


def test_lista_faltante(kit_trust):
    info = conf.cargar_listas()[conf.TSA]
    assert info["cargada"] is False and info["sha256"] is None
    assert "no encontrado" in info["motivo"]


def _listas(firmantes=True, tsa=True):
    mk = lambda ok, n: {"cargada": ok, "verificada": ok,  # noqa: E731
                        "pem": f"PEM-{n}" if ok else None, "sha256": "ab" * 32}
    return {conf.FIRMANTES: mk(firmantes, "F"), conf.TSA: mk(tsa, "T")}


def test_settings_es_offline():
    v = conf.settings_c2pa(_listas())["verify"]
    assert v["verify_trust"] is True
    assert v["ocsp_fetch"] is False
    assert v["remote_manifest_fetch"] is False


def test_settings_cierran_la_red_del_sdk():
    # allowed_network_hosts vacío bloquea todo pedido HTTP del SDK aunque otra
    # clave lo habilite. Las identidades CAWG no respetan esa lista (c2pa-rs#1645):
    # solo decode_identity_assertions las frena si el lector llega a resolverlas.
    core = conf.settings_c2pa(_listas())["core"]
    assert core["allowed_network_hosts"] == []
    assert core["decode_identity_assertions"] is False
    assert conf.settings_c2pa({})["core"] == core


def test_settings_cargan_firmantes_y_los_certificados_exclusivos_de_tsa():
    # Con las dos listas enteras, trustListUri salía una vez la de firmantes y
    # otra la de TSA según la ejecución (medido: las raíces de
    # Google y de SSL.com están en ambas). Causa, por lectura del código de
    # c2pa-rs 0.91 (no medida aparte): Settings::merge_legacy_trust_anchors pasa
    # trust.anchors por un HashSet, así que el orden cambia en cada proceso, y la
    # validación devuelve la primera lista que encadena sin mirar el tipo. Por eso
    # la TSA entra sin los certificados que comparte con la de firmantes (cargar_listas
    # deja en su "pem" solo los exclusivos). Sin anclar la TSA, c2pa-rs valida al
    # firmante con la fecha de hoy aunque el sello sea válido.
    anchors = conf.settings_c2pa(_listas())["trust"]["anchors"]
    assert [(a["trust_kind"], a["trust_anchors"]) for a in anchors] == [
        ("manifest", "PEM-F"), ("tsa", "PEM-T")]
    assert anchors[0]["trust_uri"] == f"{conf.FIRMANTES}#sha256={'ab' * 32}"
    assert anchors[1]["trust_uri"] == f"{conf.TSA}#sha256={'ab' * 32}"


# Los seis EKU que c2pa-rs acepta por defecto (sdk/src/crypto/cose/valid_eku_oids.cfg).
# Sin trust.trust_config el lector se queda con los tres que acepta por código
# (emailProtection, timeStamping, OCSPSigning) y rechaza, entre otros, el EKU de
# firma C2PA con "certificate missing required EKU".
_SEIS_EKU = {
    "1.3.6.1.5.5.7.3.4",          # emailProtection
    "1.3.6.1.5.5.7.3.36",         # documentSigning
    "1.3.6.1.5.5.7.3.8",          # timeStamping
    "1.3.6.1.5.5.7.3.9",          # OCSPSigning
    "1.3.6.1.4.1.311.76.59.1.9",  # MS C2PA signing
    "1.3.6.1.4.1.62558.2.1",      # c2pa-kp-claimSigning
}


@pytest.mark.parametrize("firmantes", [True, False])
def test_settings_aceptan_los_seis_eku_de_c2pa_rs(firmantes):
    # También sin lista de firmantes: el EKU decide válido o inválido, no confiable.
    trust_config = conf.settings_c2pa(_listas(firmantes=firmantes))["trust"]["trust_config"]
    assert set(trust_config.split()) == _SEIS_EKU
    assert trust_config.endswith("\n")


def test_sin_lista_de_firmantes_no_se_carga_ninguna_ancla():
    # Una ancla TSA sola valida firmantes en el SDK: no se carga.
    assert conf.settings_c2pa(_listas(firmantes=False))["trust"]["anchors"] == []
    assert conf.uri_lista_firmantes(_listas(firmantes=False)) is None


# ── El verificador solo acepta CONFIABLE contra la lista de firmantes ──────────

def _store_trusted(trust_uri):
    vr = {"activeManifest": {"success": [{"code": "signingCredential.trusted"},
                                         {"code": "claimSignature.validated"}],
                             "informational": [], "failure": []}}
    if trust_uri is not None:
        vr["trustListUri"] = trust_uri
    return {"active_manifest": "m", "validation_state": "Trusted",
            "validation_results": vr,
            "manifests": {"m": {"claim_generator": "X", "assertions": []}}}


URI_F = f"{conf.FIRMANTES}#sha256={'ab' * 32}"


def test_confiable_contra_lista_de_firmantes():
    info = det._extraer_info_c2pa(_store_trusted(URI_F), URI_F)
    assert info["estado_c2pa"] == "CONFIABLE"
    assert info["trust_list_uri"] == URI_F


@pytest.mark.parametrize("uri", [f"{conf.TSA}#sha256={'cd' * 32}", None])
def test_confianza_por_otra_lista_baja_a_valido_no_confiable(uri):
    info = det._extraer_info_c2pa(_store_trusted(uri), URI_F)
    assert info["estado_c2pa"] == "VALIDO_NO_CONFIABLE"
    assert info["confianza_no_atribuible"]
    assert info["firma_valida"] is True


def test_sin_uri_esperada_se_respeta_el_estado_del_sdk():
    info = det._extraer_info_c2pa(_store_trusted(None))
    assert info["estado_c2pa"] == "CONFIABLE"


def test_sello_de_tiempo_no_confiable_no_es_alteracion():
    store = _store_trusted(URI_F)
    store["validation_results"]["activeManifest"]["failure"] = [{"code": "timeStamp.untrusted"}]
    info = det._extraer_info_c2pa(store, URI_F)
    assert info["estado_c2pa"] == "CONFIABLE"
    assert det._hallazgos_fallo_c2pa(info["codigos"]) == []
