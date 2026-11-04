# -*- coding: utf-8 -*-
"""English presentation: full coverage of the tables, and same result as verificar()."""

import json
import os
import re

import pytest

pytest.importorskip("c2pa")
pytest.importorskip("cryptography")
import c2pa  # noqa: E402
from cryptography import x509  # noqa: E402

from c2pa_verify import __main__ as cli  # noqa: E402
from c2pa_verify import english as en  # noqa: E402
from c2pa_verify import listas  # noqa: E402
from c2pa_verify import verificador as det  # noqa: E402
from test_sdk import _SEIS_EKU, _bmp, _firmar, _firmar_edicion_con_ingrediente, _jpeg, _pki  # noqa: E402

_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FUENTE = "".join(open(os.path.join(_RAIZ, "src", "c2pa_verify", n), encoding="utf-8").read()
                  for n in ("verificador.py", "listas.py"))
_ESTADOS = (det.C2PA_CONFIABLE, det.C2PA_VALIDO_NO_CONFIABLE, det.C2PA_INVALIDO,
            det.C2PA_MALFORMADO, det.C2PA_REMOTO, det.C2PA_AUSENTE)


@pytest.fixture(scope="module")
def pki():
    return _pki()


def _archivo(tmp_path, datos, nombre="a.jpg"):
    ruta = tmp_path / nombre
    ruta.write_bytes(datos)
    return ruta


def _sin_espanol(r):
    """No Spanish left in the result, leaving out the file path."""
    texto = json.dumps({k: v for k, v in r.items() if k != "file"}, ensure_ascii=False)
    assert not re.search(r"[áéíóúñÁÉÍÓÚÑ]", texto), texto
    for clave in en._KEYS:
        if en._KEYS[clave] != clave:
            assert f'"{clave}"' not in texto


# ── Coverage of the tables ───────────────────────────────────────────────────

def test_todo_estado_tiene_traduccion():
    assert set(en.STATES) == set(_ESTADOS) | {None}
    assert len(set(en.STATES.values())) == len(en.STATES)


def test_todo_estado_con_rotulo_tiene_rotulo_en_ingles():
    assert set(en._LABELS) == set(det.ETIQUETA_ESTADO_C2PA)


def test_toda_descripcion_de_fallo_tiene_traduccion():
    assert set(en.FAILURES) == set(det._C2PA_DESCRIPCION_FALLO)


def test_toda_clave_del_resultado_tiene_traduccion(tmp_path):
    r = det.verificar(tmp_path / "no_existe.jpg")
    assert set(en._KEYS) == set(r)


def test_toda_clase_de_dst_tiene_traduccion():
    clases = {clase for clase, _ in det._DST_IPTC.values()} | {"informativo"}
    assert clases | {None} == set(en.TYPES)


def test_todo_asistente_tiene_traduccion():
    assert set(en._ASSISTANTS) == set(det._ACCIONES_ASISTENTE_IA)


@pytest.mark.parametrize("texto", [*en.REASONS, en._UNATTRIBUTABLE_ES, en._FINDING_MALFORMED_ES,
                                   *(p for p, _ in en._REASON_PREFIXES),
                                   "biblioteca nativa ajena en la carpeta de trabajo"])
def test_los_textos_traducidos_siguen_en_el_codigo(texto):
    # If a Spanish text changes, the translation must not silently stop applying.
    assert texto in _FUENTE


def test_todo_motivo_literal_del_codigo_esta_traducido():
    literales = re.findall(r'motivo"\]\s*=\s*(?:_MOTIVO_SIN_C2PA or )?f?"([^"]+)"', _FUENTE)
    literales += re.findall(r'motivo="([^"]+)"', _FUENTE)
    literales += re.findall(r'or "([^"]+)"\)', _FUENTE)
    assert literales
    for texto in literales:
        fijo = texto.split("{")[0]
        assert en._reason(fijo) != fijo, fijo


def test_clave_desconocida_no_pasa_en_silencio(tmp_path):
    r = det.verificar(tmp_path / "no_existe.jpg")
    r["nueva"] = 1
    with pytest.raises(KeyError):
        en.to_english(r)


# ── Same method, two presentations ───────────────────────────────────────────

def test_verify_usa_verificar_y_nada_mas(tmp_path, monkeypatch):
    llamadas = []
    original = det.verificar
    monkeypatch.setattr(det, "verificar", lambda ruta: llamadas.append(ruta) or original(ruta))
    ruta = _archivo(tmp_path, _jpeg())
    en.verify(ruta)
    assert llamadas == [ruta]


def _equivalentes(ruta):
    es, ing = det.verificar(ruta), en.verify(ruta)
    assert ing["state"] == en.STATES[es["estado"]]
    assert ing["invalidity"] == en.INVALIDITY[es["invalidez"]]
    for clave in ("sha256", "validation_state", "trust_list_uri", "digital_source_type"):
        assert ing[clave] == es[clave]
    assert ing["codes"] == es["codigos"]
    assert ing["signer"] == es["firmante"] and ing["generator"] == es["generador"]
    assert len(ing["findings"]) == len(es["hallazgos"])
    _sin_espanol(ing)
    return ing


def test_firmante_desconocido(tmp_path, pki):
    r = _equivalentes(_archivo(tmp_path, _firmar(pki)))
    assert r["state"] == "VALID_UNTRUSTED" and r["type"] == "generation" and r["findings"] == []
    assert r["label"] == "valid, signer not on the loaded trust list (manifest intact)"
    lista = r["trust_lists"][listas.FIRMANTES]
    assert lista["verified"] is True and lista["loaded"] is True and lista["certificates"] > 0


def test_archivo_alterado(tmp_path, pki):
    datos = bytearray(_firmar(pki))
    datos[-10] ^= 0xFF
    r = _equivalentes(_archivo(tmp_path, bytes(datos)))
    assert r["state"] == "INVALID" and r["invalidity"] == "integrity"
    assert any(f.startswith("C2PA assertion.dataHash.mismatch: the file content") for f in r["findings"])


def test_credencial_no_aceptada(tmp_path):
    privado = "1.3.6.1.4.1.99999.1"
    firmante = _pki(eku=x509.ObjectIdentifier(privado))
    contexto = c2pa.Context.from_dict({"trust": {"trust_config": _SEIS_EKU + privado + "\n"}})
    r = _equivalentes(_archivo(tmp_path, _firmar(firmante, contexto=contexto)))
    assert r["state"] == "INVALID" and r["invalidity"] == "credential"
    assert "content intact" in r["label"]


def test_sin_manifiesto(tmp_path):
    r = _equivalentes(_archivo(tmp_path, _jpeg()))
    assert r["state"] == "ABSENT" and r["label"] is None and r["reason"] is None


def test_ingrediente(tmp_path, pki):
    r = _equivalentes(_archivo(tmp_path, _firmar_edicion_con_ingrediente(pki, _firmar(pki))))
    ing = r["ai_ingredients"][0]
    assert ing["state"] == "VALID_UNTRUSTED" and ing["type"] == "generation" and ing["depth"] == 0


def test_formato_que_el_sdk_no_lee(tmp_path):
    r = _equivalentes(_archivo(tmp_path, _bmp(), "a.bmp"))
    assert r["state"] is None and r["reason"] == "format the SDK does not read"


def test_archivo_inexistente(tmp_path):
    r = en.verify(tmp_path / "no_existe.jpg")
    assert r["state"] is None and r["reason"].startswith("could not read the file: ")


def test_malformado_conserva_el_error_del_sdk(tmp_path, monkeypatch):
    monkeypatch.setattr(det, "_leer_c2pa", lambda *a: {"presente": False, "error": "Other: roto"})
    r = en.verify(_archivo(tmp_path, _jpeg() + b"\x00jumd\x00c2pa\x00"))
    assert r["state"] == "MALFORMED" and r["reason"] == "Other: roto"
    assert r["findings"] == ["C2PA malformed manifest: could not be read or validated"]


# ── Hand-built results, for states that need special lists ───────────────────

def test_confiable_y_confianza_no_atribuible(tmp_path):
    base = det.verificar(tmp_path / "no_existe.jpg")
    r = en.to_english(dict(base, estado="CONFIABLE"))
    assert r["state"] == "TRUSTED" and r["label"] == "valid, signer on the C2PA trust list (manifest intact)"
    r = en.to_english(dict(base, confianza_no_atribuible="lista no informada por el SDK"))
    assert r["unattributable_trust"] == "list not reported by the SDK"
    uri = "C2PA-TSA-TRUST-LIST.pem#sha256=ab"
    assert en.to_english(dict(base, confianza_no_atribuible=uri))["unattributable_trust"] == uri


def test_asistente(tmp_path):
    base = det.verificar(tmp_path / "no_existe.jpg")
    a = {"nombre": "Claude, de Anthropic", "accion": "com.anthropic.claude.provided", "confianza_origen": None}
    assert en.to_english(dict(base, asistente_ia=a))["ai_assistant"]["name"] == "Claude, by Anthropic"


def test_fallo_sin_descripcion_propia(tmp_path):
    base = det.verificar(tmp_path / "no_existe.jpg")
    r = en.to_english(dict(base, hallazgos=["C2PA codigo.nuevo: fallo de validación del manifiesto"]))
    assert r["findings"] == ["C2PA codigo.nuevo: manifest validation failure"]


def test_biblioteca_ajena():
    assert en._reason("biblioteca nativa ajena en la carpeta de trabajo (C:\\x\\c2pa_c.dll): no se cargó") == (
        "foreign native library in the working directory (C:\\x\\c2pa_c.dll): not loaded")


# ── Command line ─────────────────────────────────────────────────────────────

def test_cli_espanol_por_defecto_sin_cambios(tmp_path, pki, capsys):
    ruta = _archivo(tmp_path, _firmar(pki))
    assert cli.main([str(ruta)]) == 0
    salida = capsys.readouterr().out
    assert "Estado: VALIDO_NO_CONFIABLE" in salida and "Firmante declarado" in salida


def test_cli_ingles(tmp_path, pki, capsys):
    ruta = _archivo(tmp_path, _firmar(pki))
    assert cli.main(["--lang", "en", str(ruta)]) == 0
    salida = capsys.readouterr().out
    assert "State: VALID_UNTRUSTED" in salida and "Declared signer" in salida
    assert "Estado" not in salida


def test_cli_ingles_json(tmp_path, pki, capsys):
    ruta = _archivo(tmp_path, _firmar(pki))
    assert cli.main(["--lang", "en", "--json", str(ruta)]) == 0
    assert json.loads(capsys.readouterr().out)[0]["state"] == "VALID_UNTRUSTED"


def test_cli_el_idioma_no_depende_de_la_maquina(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setenv("LC_ALL", "en_US.UTF-8")
    assert cli.main([str(_archivo(tmp_path, _jpeg()))]) == 0
    assert "Estado: AUSENTE" in capsys.readouterr().out


def test_cli_archivo_faltante_en_ingles(tmp_path, capsys):
    assert cli.main(["--lang", "en", str(tmp_path / "no_existe.jpg")]) == 1
    salida = capsys.readouterr().out
    assert "State: not determined" in salida and "could not read the file" in salida


# ── Documentation ────────────────────────────────────────────────────────────

def test_cada_readme_nombra_todos_sus_estados():
    with open(os.path.join(_RAIZ, "README.md"), encoding="utf-8") as f:
        ingles = f.read()
    with open(os.path.join(_RAIZ, "README.es.md"), encoding="utf-8") as f:
        espanol = f.read()
    for estado in _ESTADOS:
        assert f"`{en.STATES[estado]}`" in ingles
        assert estado in espanol
