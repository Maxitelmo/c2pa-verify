# -*- coding: utf-8 -*-
"""API pública (0.3.0) que no necesita el SDK: nombres, parser y atajos del paquete."""

import os
import subprocess
import sys

import c2pa_verify
from c2pa_verify import verificador as det
from test_parser import _store

_NUEVOS = ("leer_manifiesto", "extraer_info", "sdk_disponible", "motivo_sin_sdk",
           "sdk_no_lee", "reiniciar")


def test_version():
    assert c2pa_verify.__version__ == "0.3.0"


def test_nombres_publicos_en_el_modulo_y_el_paquete():
    for nombre in _NUEVOS:
        assert callable(getattr(det, nombre)), nombre
        assert callable(getattr(c2pa_verify, nombre)), nombre


def test_extraer_info_es_el_parser():
    uri = "C2PA-TRUST-LIST.pem#sha256=abc"
    results = {"trustListUri": uri, "activeManifest": {
        "success": [{"code": "signingCredential.trusted"}], "informational": [], "failure": []}}
    roto = {"validation_results": {"activeManifest": {
        "failure": [{"code": "claimSignature.missing"}]}}}
    for store in (_store(dst="trainedAlgorithmicMedia", estado="Valid"),
                  _store(results=results), roto, {}):
        for lista in (None, uri, "otra"):
            esperado = det._extraer_info_c2pa(store, lista)
            assert det.extraer_info(store, lista) == esperado
            assert c2pa_verify.extraer_info(store, lista) == esperado
    assert det.extraer_info(_store(results=results), uri)["estado_c2pa"] == "CONFIABLE"
    assert det.extraer_info(_store(results=results), "otra")["estado_c2pa"] == "VALIDO_NO_CONFIABLE"
    assert det.extraer_info(_store(results=results))["estado_c2pa"] == "CONFIABLE"
    assert det.extraer_info(roto)["estado_c2pa"] == "MALFORMADO"
    assert det.extraer_info(roto)["presente"] is False
    assert det.extraer_info({})["estado_c2pa"] == "AUSENTE"


def test_motivo_sin_sdk_es_el_del_modulo(monkeypatch):
    monkeypatch.setattr(det, "_MOTIVO_SIN_C2PA", "motivo de prueba")
    assert det.motivo_sin_sdk() == "motivo de prueba"
    assert c2pa_verify.motivo_sin_sdk() == "motivo de prueba"
    monkeypatch.setattr(det, "_MOTIVO_SIN_C2PA", None)
    assert det.motivo_sin_sdk() is None


def test_sdk_disponible_y_sdk_no_lee_sin_sdk(monkeypatch):
    monkeypatch.setattr(det, "_importar_c2pa", lambda: None)
    monkeypatch.setattr(det, "_MIME_SDK", None)
    assert det.sdk_disponible() is False
    assert c2pa_verify.sdk_disponible() is False
    # Sin la lista de formatos del SDK no se rotula nada como no soportado.
    assert det.sdk_no_lee(b"BM" + bytes(60)) is False
    assert c2pa_verify.sdk_no_lee(b"BM" + bytes(60)) is False
    assert det.sdk_no_lee(b"\xff\xd8\xff") is False


def test_reiniciar_descarta_el_contexto(monkeypatch):
    monkeypatch.setattr(det, "_CONTEXTO_C2PA", ("contexto", {}, None))
    det.reiniciar()
    assert det._CONTEXTO_C2PA is None
    monkeypatch.setattr(det, "_CONTEXTO_C2PA", ("contexto", {}, None))
    c2pa_verify.reiniciar()
    assert det._CONTEXTO_C2PA is None


def test_los_atajos_importan_el_verificador_recien_al_usarlos():
    codigo = ("import sys, c2pa_verify\n"
              "assert 'c2pa_verify.verificador' not in sys.modules\n"
              "assert c2pa_verify.extraer_info({})['estado_c2pa'] == 'AUSENTE'\n"
              "assert 'c2pa_verify.verificador' in sys.modules\n")
    # El subproceso no hereda el pythonpath de pytest: sin instalar, no hallaría el paquete.
    entorno = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(det.__file__)))
    salida = subprocess.run([sys.executable, "-c", codigo], env=entorno, capture_output=True)
    assert salida.returncode == 0, salida.stderr
