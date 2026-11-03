# -*- coding: utf-8 -*-
"""Parser puro del JSON de un manifiesto (sin I/O ni SDK)."""

import pytest

from c2pa_verify import verificador as det


_DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"


def _store(*, dst=None, estado=None, status=None, generador="OpenAI-API",
           ingredientes=None, extra_manifests=None, results=None, firmante=None):
    """Manifest store con la forma del JSON de c2pa-python (Reader.json())."""
    acciones = [{"action": "c2pa.created"}]
    if dst:
        acciones[0]["digitalSourceType"] = _DST + dst
    firmante = firmante or generador
    activo = {
        "claim_generator_info": [{"name": generador, "version": "1.0"}],
        "signature_info": {"issuer": firmante, "common_name": firmante},
        "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": acciones}}],
        "ingredients": ingredientes or [],
        "label": "urn:c2pa:activo",
    }
    store = {"active_manifest": "urn:c2pa:activo",
             "manifests": {"urn:c2pa:activo": activo}}
    store["manifests"].update(extra_manifests or {})
    if estado is not None:
        store["validation_state"] = estado
    if status is not None:
        store["validation_status"] = status
    if results is not None:
        store["validation_results"] = results
    return store


def _manifiesto_ia(label="urn:c2pa:ingrediente", firmante="OpenAI"):
    return {label: {
        "claim_generator_info": [{"name": "ChatGPT", "version": "1"}],
        "signature_info": {"issuer": firmante, "common_name": firmante},
        "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": [
            {"action": "c2pa.created",
             "digitalSourceType": _DST + "trainedAlgorithmicMedia"}]}}],
        "label": label,
    }}


def _ingrediente(label="urn:c2pa:ingrediente"):
    return {"title": "imagen_ia.png", "relationship": "parentOf",
            "active_manifest": label}


_RESULTS_CREDENCIAL_NO_ACEPTADA = {"activeManifest": {
    "success": [{"code": c} for c in (
        "signingCredential.ocsp.notRevoked", "timeStamp.validated",
        "claimSignature.insideValidity", "claimSignature.validated",
        "assertion.hashedURI.match", "assertion.dataHash.match")],
    "informational": [{"code": "timeStamp.untrusted"}],
    "failure": [{"code": "signingCredential.untrusted"},
                {"code": "signingCredential.invalid",
                 "explanation": "certificate missing required EKU"}]}}


def _results(success=(), informational=(), failure=()):
    mk = lambda cs: [{"code": c, "url": "self#jumbf=/c2pa", "explanation": c} for c in cs]  # noqa: E731
    return {"activeManifest": {"success": mk(success), "informational": mk(informational),
                               "failure": mk(failure)}, "specVersion": "2.4.0"}


_EXITO_BASE = ("claimSignature.insideValidity", "claimSignature.validated",
               "assertion.hashedURI.match", "assertion.dataHash.match")


_URL_REMOTA = "https://manifiestos.example.test/m.c2pa"


def _sdk_que_lanza(error):
    class Reader:
        def __init__(self, *a, **k):
            raise error
    return type("c2pa", (), {"Reader": Reader})


def _ai_remoto(url=_URL_REMOTA):
    return {"aplica": True, "nivel": "BAJO", "tipo_ia": None, "generador": None,
            "indicadores": [], "notas": [f"{det._NOTA_C2PA_REMOTO}. Dirección declarada: {url}"],
            "estado_c2pa": "REMOTO", "hallazgos_c2pa": [],
            "datos_crudos": {"C2PA": {"estado_c2pa": "REMOTO", "url_remota": url}}}


def test_extraer_info_c2pa_generacion_y_firmante():
    info = det._extraer_info_c2pa(_store(dst="trainedAlgorithmicMedia", estado="Trusted"))
    assert info["presente"] is True
    assert info["tipo"] == "generacion"
    assert info["generador"] == "OpenAI-API"


def test_extraer_info_c2pa_digital_capture():
    info = det._extraer_info_c2pa(_store(dst="digitalCapture", estado="Trusted"))
    assert info["tipo"] == "captura"


def test_extraer_info_c2pa_sin_manifiestos():
    assert det._extraer_info_c2pa({"manifests": {}})["presente"] is False


@pytest.mark.parametrize("valor,clase", [
    (_DST + "compositeWithTrainedAlgorithmicMedia", "edicion_ia"),
    (_DST + "compositeSynthetic", "edicion_ia"),
    (_DST + "virtualRecording", "informativo"),
    (_DST + "trainedAlgorithmicMedia", "generacion"),
    (_DST + "trainedAlgorithmicData", "generacion"),
    ("c2pa.trainedAlgorithmicData", "generacion"),
    (_DST + "algorithmicMedia", "algoritmico"),
    (_DST + "computationalCapture", "captura"),
    (_DST + "print", "captura"),
    (_DST + "screenCapture", "informativo"),
    ("", None),
])
def test_r8_clasificacion_de_valores_estructurados(valor, clase):
    assert det._clasificar_digital_source_type(valor) == clase


def test_r1_valid_y_trusted_son_distintos():
    valid = det._extraer_info_c2pa(_store(dst="trainedAlgorithmicMedia", estado="Valid"))
    trusted = det._extraer_info_c2pa(_store(dst="trainedAlgorithmicMedia", estado="Trusted"))
    assert valid["estado_c2pa"] == "VALIDO_NO_CONFIABLE"
    assert trusted["estado_c2pa"] == "CONFIABLE"


def test_r4_untrusted_es_valido_no_confiable():
    info = det._extraer_info_c2pa(_store(
        dst="trainedAlgorithmicMedia",
        status=[{"code": "signingCredential.untrusted"}]))
    assert info["estado_c2pa"] == "VALIDO_NO_CONFIABLE"
    assert info["firma_valida"] is True


@pytest.mark.parametrize("codigo", ["signingCredential.expired", "signingCredential.revoked",
                                    "signingCredential.ocsp.revoked"])
def test_r5a_otros_fallos_de_credencial(codigo):
    store = _store(dst="trainedAlgorithmicMedia", estado="Invalid",
                   status=[{"code": codigo}])
    info = det._extraer_info_c2pa(store)
    assert info["estado_c2pa"] == "INVALIDO"
    assert info["invalidez"] == "credencial"


def test_r5a_ingrediente_con_credencial_no_aceptada_suma():
    ing = _ingrediente()
    ing["validation_results"] = _RESULTS_CREDENCIAL_NO_ACEPTADA
    store = _store(estado="Trusted", ingredientes=[ing], extra_manifests=_manifiesto_ia())
    i = det._extraer_info_c2pa(store)["ingredientes_ia"][0]
    assert i["estado_c2pa"] == "INVALIDO" and i["invalidez"] == "credencial"


@pytest.mark.parametrize("estado_sdk,results,esperado", [
    # Firmante fuera de la lista cargada: el SDK dice "Valid".
    ("Valid", _results(_EXITO_BASE, ["signingCredential.ocsp.skipped"],
                       ["signingCredential.untrusted"]), "VALIDO_NO_CONFIABLE"),
    # Firmante en la lista cargada.
    ("Trusted", _results(("signingCredential.trusted",) + _EXITO_BASE,
                         ["signingCredential.ocsp.skipped"]), "CONFIABLE"),
    # Byte alterado después de la firma, aun con firmante confiable.
    ("Invalid", _results(("signingCredential.trusted",) + _EXITO_BASE[:3],
                         ["signingCredential.ocsp.skipped"],
                         ["assertion.dataHash.mismatch"]), "INVALIDO"),
    # verify_trust desactivado: íntegro, sin juicio de confianza.
    ("Valid", _results(_EXITO_BASE, ["signingCredential.ocsp.skipped"]), "VALIDO_NO_CONFIABLE"),
])
def test_estado_desde_validation_results(estado_sdk, results, esperado):
    info = det._extraer_info_c2pa(_store(dst="trainedAlgorithmicMedia",
                                         estado=estado_sdk, results=results))
    assert info["estado_c2pa"] == esperado
    assert info["codigos"]["informational"] == ["signingCredential.ocsp.skipped"]


def test_validation_results_prevalece_sobre_validation_status():
    info = det._extraer_info_c2pa(_store(
        estado="Valid", status=[{"code": "algo.raro"}],
        results=_results(_EXITO_BASE, [], ["signingCredential.untrusted"])))
    assert info["codigos"]["failure"] == ["signingCredential.untrusted"]
    assert info["estado_c2pa"] == "VALIDO_NO_CONFIABLE"


def test_firmante_desde_signature_info():
    info = det._extraer_info_c2pa(_store(estado="Valid", generador="Pixel Camera"))
    assert info["firmante"] == "Pixel Camera"


def test_sin_manifiestos_con_fallos_es_malformado():
    info = det._extraer_info_c2pa({"manifests": {},
                                   "validation_status": [{"code": "claim.malformed"}]})
    assert info["presente"] is False
    assert info["estado_c2pa"] == "MALFORMADO"


def test_r6_ingrediente_ia_se_reporta_aparte():
    store = _store(dst=None, estado="Trusted", generador="Adobe Photoshop",
                   ingredientes=[_ingrediente()], extra_manifests=_manifiesto_ia())
    info = det._extraer_info_c2pa(store)
    assert info["tipo"] is None          # el activo no declara DST de IA
    ing = info["ingredientes_ia"]
    assert len(ing) == 1
    assert ing[0]["manifiesto"] == "urn:c2pa:ingrediente"
    assert ing[0]["firmante"] == "OpenAI"
    assert ing[0]["digital_source_type"].endswith("trainedAlgorithmicMedia")


def test_r6_ingrediente_ia_anidado_y_ciclo():
    # activo -> intermedio (sin DST) -> IA; con una referencia circular.
    intermedio = {"urn:c2pa:intermedio": {
        "claim_generator": "Editor", "assertions": [],
        "ingredients": [_ingrediente("urn:c2pa:ia"), _ingrediente("urn:c2pa:activo")]}}
    store = _store(estado="Trusted", ingredientes=[_ingrediente("urn:c2pa:intermedio")],
                   extra_manifests={**intermedio, **_manifiesto_ia("urn:c2pa:ia")})
    ing = det._extraer_info_c2pa(store)["ingredientes_ia"]
    assert [(i["manifiesto"], i["profundidad"]) for i in ing] == [("urn:c2pa:ia", 1)]


def test_r6_estado_del_ingrediente_suma_los_deltas_del_sdk():
    # Al incorporarlo el editor no confiaba en el firmante; al leer, el SDK sí
    # (ingredientDeltas), contra la lista de firmantes.
    ing = _ingrediente()
    ing["label"] = "c2pa.ingredient.v3"
    ing["validation_results"] = {"activeManifest": {
        "success": [{"code": "claimSignature.validated"}], "informational": [],
        "failure": [{"code": "signingCredential.untrusted"}]}}
    uri = "C2PA-TRUST-LIST.pem#sha256=ab"
    results = {"activeManifest": {"success": [], "informational": [], "failure": []},
               "ingredientDeltas": [{
                   "ingredientAssertionURI": "self#jumbf=/c2pa/urn:c2pa:activo/c2pa.assertions/c2pa.ingredient.v3",
                   "validationDeltas": {"success": [{
                       "code": "signingCredential.trusted",
                       "explanation": f"signing certificate trusted, found in [{uri}] trust anchors"}],
                       "informational": [], "failure": []}}]}
    store = _store(estado="Valid", ingredientes=[ing], extra_manifests=_manifiesto_ia(),
                   results=results)
    assert det._extraer_info_c2pa(store, uri)["ingredientes_ia"][0]["estado_c2pa"] == "CONFIABLE"
    otra = det._extraer_info_c2pa(store, "OTRA.pem")["ingredientes_ia"][0]["estado_c2pa"]
    assert otra == "VALIDO_NO_CONFIABLE"


def test_n2_error_remoto_del_sdk_es_estado_remoto():
    sdk = _sdk_que_lanza(Exception(f"Remote: must fetch remote manifests from url {_URL_REMOTA}"))
    assert det._leer_c2pa(sdk, "a.jpg", object(), None) == {
        "presente": False, "estado_c2pa": "REMOTO", "url_remota": _URL_REMOTA}


def test_n2_subclase_remote_manifest_sin_url():
    class RemoteManifest(Exception):
        pass
    info = det._leer_c2pa(_sdk_que_lanza(RemoteManifest("RemoteManifest: remoto")),
                          "a.jpg", object(), None)
    assert info["estado_c2pa"] == "REMOTO" and info["url_remota"] is None


@pytest.mark.parametrize("error", [
    Exception("NotSupported: type is unsupported"),
    type("_C2paNotSupported", (Exception,), {})("type is unsupported"),
])
def test_n7_not_supported_no_es_error_de_lectura(error):
    info = det._leer_c2pa(_sdk_que_lanza(error), "a.bmp", object(), None)
    assert info == {"presente": False, "no_soportado": True}
