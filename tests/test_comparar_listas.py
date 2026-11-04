# -*- coding: utf-8 -*-
"""Comparador de listas de confianza, sin red: la descarga se simula."""

import importlib.util
import json
import os

import pytest

from c2pa_verify import listas

_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "comparar_listas", os.path.join(_RAIZ, "tools", "comparar_listas.py"))
comp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(comp)

_COMMIT = "abc123"


def _pem(*contenidos):
    return "".join(f"-----BEGIN CERTIFICATE-----\n{c}\n-----END CERTIFICATE-----\n"
                   for c in contenidos).encode("ascii")


def _locales():
    out = {}
    for nombre in (listas.FIRMANTES, listas.TSA):
        with open(os.path.join(listas._dirs_trust()[0], nombre), "rb") as f:
            out[nombre] = f.read()
    return out


def _descarga(remotas):
    def descargar(url, token=None):
        if url == comp.API_COMMITS:
            return json.dumps([{"sha": _COMMIT, "commit": {"committer": {"date": "2026-11-01T00:00:00Z"}}}]).encode()
        for nombre, datos in remotas.items():
            if url == comp.RAW.format(commit=_COMMIT, nombre=nombre):
                return datos
        raise AssertionError(f"URL inesperada: {url}")
    return descargar


def test_listas_iguales_salen_con_cero(capsys):
    assert comp.main(_descarga(_locales())) == comp.SALIDA_IGUALES
    salida = capsys.readouterr().out
    assert "cambió" not in salida and _COMMIT in salida


def test_lista_distinta_avisa_con_codigo_propio(capsys):
    remotas = _locales()
    remotas[listas.TSA] += _pem("QUJD")
    assert comp.main(_descarga(remotas)) == comp.SALIDA_NUEVAS
    salida = capsys.readouterr().out
    assert "cambió" in salida and "trust/README.md" in salida


def test_cuenta_certificados_agregados_y_quitados():
    r = comp.comparar({listas.FIRMANTES: _pem("QQ==", "Qg=="), listas.TSA: _pem("Qw==")},
                      {listas.FIRMANTES: _pem("Qg==", "RA==", "RQ=="), listas.TSA: _pem("Qw==")})
    f = r[listas.FIRMANTES]
    assert f["cambio"] is True
    assert (f["agregados"], f["quitados"], f["total"]) == (2, 1, 3)
    assert r[listas.TSA]["cambio"] is False


def test_mismos_certificados_con_otros_bytes_igual_avisa():
    # El hash fijado es del archivo: cualquier byte distinto obliga a revisarlo.
    r = comp.comparar({listas.FIRMANTES: _pem("QQ=="), listas.TSA: _pem("Qw==")},
                      {listas.FIRMANTES: _pem("QQ==") + b"\n", listas.TSA: _pem("Qw==")})
    assert r[listas.FIRMANTES]["cambio"] is True
    assert r[listas.FIRMANTES]["agregados"] == 0


@pytest.mark.parametrize("error", [OSError("sin red"), KeyError("sha"), IndexError("vacío")])
def test_si_no_puede_comparar_nunca_informa_sin_cambios(capsys, error):
    def falla(url, token=None):
        raise error
    assert comp.main(falla) == comp.SALIDA_ERROR
    assert capsys.readouterr().out == ""


def test_fuente_que_no_es_pem_es_error(capsys):
    remotas = _locales()
    remotas[listas.FIRMANTES] = "certificado ñ".encode("utf-8")
    assert comp.main(_descarga(remotas)) == comp.SALIDA_ERROR
