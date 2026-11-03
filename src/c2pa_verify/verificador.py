# -*- coding: utf-8 -*-
"""Verificación offline de manifiestos C2PA sobre c2pa-python.

Informa el estado de la firma y lo que el manifiesto declara. No puntúa ni opina
sobre si el contenido es verdadero: una firma confiable dice quién firmó y que el
archivo no cambió desde entonces; la ausencia de manifiesto no dice nada.

Punto de entrada: verificar(ruta). El resto es privado.

Verificado contra c2pa-python 0.38.0 (c2pa-rs 0.91.0); ver docs/HALLAZGOS-SDK.md.
"""

import datetime as _dt
import hashlib
import os
import re
import sys
import threading

from . import __version__
from . import listas as _c2pa_confianza

NO_DISPONIBLE = "no disponible"
_TAM_BLOQUE = 1024 * 1024
_TAM_CABECERA = 8 * 1024 * 1024   # donde se busca la dirección de un manifiesto remoto


# Vocabulario IPTC DigitalSourceType con clase propia; el resto es "informativo".
_DST_IPTC = {
    "compositewithtrainedalgorithmicmedia":
        ("edicion_ia", "contenido editado o compuesto con IA generativa"),
    "compositesynthetic":
        ("edicion_ia", "composición con al menos un elemento sintético"),
    "trainedalgorithmicmedia":
        ("generacion", "contenido creado con IA generativa"),
    "trainedalgorithmicdata":
        ("generacion", "datos generados por un modelo entrenado"),
    "algorithmicmedia":
        ("algoritmico", "contenido creado por un algoritmo sin modelo entrenado: "
                        "algorítmico, no generativo"),
    "digitalcapture":       ("captura", "captura de cámara digital"),
    "computationalcapture": ("captura", "captura con procesamiento computacional del dispositivo"),
    "negativefilm":         ("captura", "digitalización de un negativo fotográfico"),
    "positivefilm":         ("captura", "digitalización de una diapositiva"),
    "print":                ("captura", "digitalización de una copia impresa"),
}


# Prioridad entre clases cuando un manifiesto declara más de un valor.
_PRIORIDAD_CLASE_DST = {"edicion_ia": 0, "generacion": 1, "captura": 2,
                        "algoritmico": 3, "informativo": 4}


def _cola_dst(valor: str) -> str:
    """Último segmento del URI (o de 'c2pa.algo'): el término IPTC."""
    return re.split(r"[/#:.]", (valor or "").strip())[-1]


def _clasificar_digital_source_type(valor: str):
    """Clase de un valor IPTC DigitalSourceType: 'generacion' | 'edicion_ia' |
    'algoritmico' | 'captura' | 'informativo', o None si está vacío."""
    cola = _cola_dst(valor).lower()
    if not cola:
        return None
    return _DST_IPTC.get(cola, ("informativo", ""))[0]


# Estados del manifiesto: bien formado, válido (íntegro) y confiable (íntegro y
# con el firmante en la lista cargada) son cosas distintas. REMOTO: el archivo
# remite a un manifiesto en internet (dcterms:provenance); no se descarga.
C2PA_AUSENTE             = "AUSENTE"
C2PA_MALFORMADO          = "MALFORMADO"
C2PA_REMOTO              = "REMOTO"
C2PA_INVALIDO            = "INVALIDO"
C2PA_VALIDO_NO_CONFIABLE = "VALIDO_NO_CONFIABLE"
C2PA_CONFIABLE           = "CONFIABLE"


# Fallos que hablan de la confianza, no de la integridad: con ellos el
# manifiesto sigue siendo válido, solo que el firmante (o la autoridad del sello
# de tiempo) no está en la lista cargada.
_C2PA_FALLOS_DE_CONFIANZA = frozenset({"signingCredential.untrusted",
                                       "timeStamp.untrusted"})


# Fallos de la CREDENCIAL del firmante (certificado no apto, vencido o
# revocado). Dejan el manifiesto inválido, pero sin ningún fallo de integridad
# el contenido es el que se firmó.
_C2PA_FALLOS_DE_CREDENCIAL = frozenset({
    "signingCredential.invalid", "signingCredential.expired",
    "signingCredential.revoked", "signingCredential.ocsp.revoked",
})


# Tipo de invalidez de un manifiesto INVALIDO.
C2PA_INVALIDEZ_CREDENCIAL = "credencial"
C2PA_INVALIDEZ_INTEGRIDAD = "integridad"


# Formato viejo validation_status, sin la clasificación del SDK.
_C2PA_CODIGOS_INFORMATIVOS = frozenset({
    "algorithm.deprecated",
    "signingCredential.ocsp.skipped",
    "signingCredential.ocsp.inaccessible",
    "signingCredential.ocsp.unknown",
})
_C2PA_SUFIJOS_EXITO = (".validated", ".match", ".trusted", ".insideValidity",
                       ".notRevoked", ".accessible")


_C2PA_DESCRIPCION_FALLO = {
    # Lo verificado es que el contenido no es el firmado: puede haber cambiado
    # después de la firma, o el manifiesto puede venir de otro contenido.
    "assertion.dataHash.mismatch":
        "el contenido del archivo no coincide con el que se firmó (cambió después "
        "de la firma, o el manifiesto corresponde a otro contenido)",
    "assertion.bmffHash.mismatch":
        "el contenido del archivo no coincide con el que se firmó (cambió después "
        "de la firma, o el manifiesto corresponde a otro contenido)",
    "assertion.boxesHash.mismatch":
        "el contenido del archivo no coincide con el que se firmó (cambió después "
        "de la firma, o el manifiesto corresponde a otro contenido)",
    "assertion.collectionHash.mismatch":
        "el contenido no coincide con el hash firmado de la colección",
    "assertion.hashedURI.mismatch":
        "una aserción del manifiesto no coincide con la que se firmó",
    "claimSignature.mismatch": "la firma del manifiesto no verifica",
    "signingCredential.revoked": "el certificado del firmante figura revocado",
    "signingCredential.ocsp.revoked": "el certificado del firmante figura revocado",
    "signingCredential.expired": "el certificado del firmante estaba vencido",
    "signingCredential.invalid":
        "el certificado del firmante no es apto para firmar manifiestos",
}


# Rótulo del estado de la FIRMA. "Confiable" a secas se lee como "contenido
# confiable": el rótulo dice qué se verificó.
ETIQUETA_ESTADO_C2PA = {
    C2PA_CONFIABLE:
        "válida, firmante en la lista de confianza C2PA (manifiesto íntegro)",
    C2PA_VALIDO_NO_CONFIABLE:
        "válida, firmante fuera de la lista de confianza cargada (manifiesto íntegro)",
    C2PA_INVALIDO:
        "inválida (el contenido no coincide con el que se firmó, o la firma no verifica)",
    C2PA_MALFORMADO: "no verificable (manifiesto presente pero ilegible)",
    C2PA_REMOTO: "no verificada (manifiesto en una dirección remota que no se descarga)",
}


def etiqueta_estado_c2pa(estado, invalidez=None):
    """Rótulo del estado de la firma para informes, o None (AUSENTE / sin estado)."""
    if estado == C2PA_INVALIDO and invalidez == C2PA_INVALIDEZ_CREDENCIAL:
        return "no aceptada: certificado del firmante no válido (contenido íntegro)"
    return ETIQUETA_ESTADO_C2PA.get(estado)


def _buscar_digital_source_types(assertions) -> list:
    """Recorre recursivamente las assertions buscando todo valor 'digitalSourceType'.

    En C2PA la aserción puede ser stds.iptc.photo-metadata
    (Iptc4xmpExt:DigitalSourceType) o c2pa.actions (cada acción con su
    digitalSourceType). Se busca por nombre de clave, sin asumir la estructura.
    """
    encontrados: list = []

    def _walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and k.lower().endswith("digitalsourcetype") and isinstance(v, str):
                    encontrados.append(v)
                else:
                    _walk(v)
        elif isinstance(o, list):
            for it in o:
                _walk(it)

    _walk(assertions)
    return encontrados


def _codigos_c2pa(manifest_store: dict, activo: dict):
    """Códigos de validación del manifiesto activo, separados en
    {"success", "informational", "failure"} (listas de códigos), o None si el
    JSON no trae validación.

    Lee validation_results (c2pa-python >= 0.6x: el SDK ya los clasifica). Si no
    está, cae a validation_status (formato viejo: lista sin clasificar)."""
    vr = manifest_store.get("validation_results")
    if isinstance(vr, dict):
        am = vr.get("activeManifest") or {}
        return {
            k: [s.get("code") for s in (am.get(k) or [])
                if isinstance(s, dict) and s.get("code")]
            for k in ("success", "informational", "failure")
        }
    vs = manifest_store.get("validation_status")
    if vs is None:
        vs = activo.get("validation_status") if isinstance(activo, dict) else None
    if not isinstance(vs, list):
        return None
    out = {"success": [], "informational": [], "failure": []}
    for s in vs:
        code = s.get("code") if isinstance(s, dict) else s
        if not isinstance(code, str) or not code:
            continue
        if code in _C2PA_CODIGOS_INFORMATIVOS:
            out["informational"].append(code)
        elif code.endswith(_C2PA_SUFIJOS_EXITO):
            out["success"].append(code)
        else:
            out["failure"].append(code)
    return out


def _estado_c2pa(validation_state, codigos):
    """Estado del manifiesto activo a partir de los códigos (prioridad) o del
    validation_state del SDK. Nunca afirma CONFIABLE sin evidencia."""
    sdk = {"trusted": C2PA_CONFIABLE, "valid": C2PA_VALIDO_NO_CONFIABLE,
           "invalid": C2PA_INVALIDO}.get(str(validation_state or "").lower())
    if codigos is None:
        return sdk
    if [c for c in codigos["failure"] if c not in _C2PA_FALLOS_DE_CONFIANZA]:
        return C2PA_INVALIDO
    if "signingCredential.trusted" in codigos["success"]:
        return C2PA_CONFIABLE
    if any(c in _C2PA_FALLOS_DE_CONFIANZA for c in codigos["failure"]):
        return C2PA_VALIDO_NO_CONFIABLE
    if sdk == C2PA_CONFIABLE:
        return C2PA_CONFIABLE
    return C2PA_VALIDO_NO_CONFIABLE


def _tipo_invalidez(codigos):
    """Para un manifiesto INVALIDO: "credencial" si todos sus fallos (fuera de
    los de confianza) son de la credencial del firmante; si no, "integridad".
    Sin códigos detallados, el criterio estricto (integridad)."""
    fallos = [c for c in (codigos or {}).get("failure") or []
              if c not in _C2PA_FALLOS_DE_CONFIANZA]
    if fallos and all(c in _C2PA_FALLOS_DE_CREDENCIAL for c in fallos):
        return C2PA_INVALIDEZ_CREDENCIAL
    return C2PA_INVALIDEZ_INTEGRIDAD


def _extraer_info_c2pa(manifest_store: dict, uri_firmantes=None) -> dict:
    """Parser puro del JSON de un manifiesto C2PA (sin I/O, testeable).

    `uri_firmantes`: si se pasa (la capa firmada cargó listas de confianza),
    CONFIABLE exige que el SDK informe haber validado contra esa lista
    (validation_results.trustListUri). Con otra lista, o sin dato, el estado
    baja a VALIDO_NO_CONFIABLE y se anota en confianza_no_atribuible.

    Retorna dict con: presente, estado_c2pa (C2PA_*), codigos
    ({success, informational, failure} o None), firma_valida (alias derivado
    del estado: True/False/None), validation_state (crudo del SDK),
    trust_list_uri, confianza_no_atribuible, generador, firmante,
    digital_source_type, tipo ('generacion'|'edicion_ia'|'captura'|None).
    """
    out = {
        "presente": True,
        "estado_c2pa": None,
        "codigos": None,
        "firma_valida": None,
        "validation_state": None,
        "trust_list_uri": None,
        "confianza_no_atribuible": None,
        "invalidez": None,
        "generador": None,
        "firmante": None,
        "digital_source_type": None,
        "tipo": None,
        "ingredientes_ia": [],
        "asistente_ia": None,
    }
    manifests = manifest_store.get("manifests") or {}
    activo_id = manifest_store.get("active_manifest")
    activo = manifests.get(activo_id) if activo_id else None
    if activo is None and manifests:
        activo = next(iter(manifests.values()))
    if not isinstance(activo, dict):
        # Sin manifiesto legible: con códigos de fallo es un manifiesto roto.
        codigos = _codigos_c2pa(manifest_store, {})
        out["presente"] = False
        out["codigos"] = codigos
        out["estado_c2pa"] = (C2PA_MALFORMADO if codigos and codigos["failure"]
                              else C2PA_AUSENTE)
        if out["estado_c2pa"] == C2PA_MALFORMADO:
            out["firma_valida"] = False
        return out

    # Generador: claim_generator_info (API nueva, lista de {name,version}) o claim_generator (str)
    cgi = activo.get("claim_generator_info")
    if isinstance(cgi, list) and cgi and isinstance(cgi[0], dict) and cgi[0].get("name"):
        out["generador"] = cgi[0]["name"]
    else:
        out["generador"] = activo.get("claim_generator")
    sig = activo.get("signature_info")
    if isinstance(sig, dict):
        out["firmante"] = sig.get("issuer") or sig.get("common_name")

    # Validación: estado categórico + códigos crudos. firma_valida queda como
    # alias por compatibilidad (True = manifiesto íntegro, confiable o no).
    estado_sdk = manifest_store.get("validation_state") or activo.get("validation_state")
    out["validation_state"] = estado_sdk
    out["codigos"] = _codigos_c2pa(manifest_store, activo)
    out["estado_c2pa"] = _estado_c2pa(estado_sdk, out["codigos"])
    vr = manifest_store.get("validation_results")
    if isinstance(vr, dict):
        out["trust_list_uri"] = vr.get("trustListUri")
    # El SDK no aísla las listas por tipo (una ancla TSA valida firmantes): solo
    # cuenta como confiable si validó contra la lista de firmantes.
    if (uri_firmantes and out["estado_c2pa"] == C2PA_CONFIABLE
            and out["trust_list_uri"] != uri_firmantes):
        out["estado_c2pa"] = C2PA_VALIDO_NO_CONFIABLE
        out["confianza_no_atribuible"] = out["trust_list_uri"] or "lista no informada por el SDK"
    if out["estado_c2pa"] in (C2PA_VALIDO_NO_CONFIABLE, C2PA_CONFIABLE):
        out["firma_valida"] = True
    elif out["estado_c2pa"] in (C2PA_INVALIDO, C2PA_MALFORMADO):
        out["firma_valida"] = False
    if out["estado_c2pa"] == C2PA_INVALIDO:
        out["invalidez"] = _tipo_invalidez(out["codigos"])

    # DigitalSourceType DEL ACTIVO (solo las aserciones del manifiesto activo).
    out["digital_source_type"], out["tipo"] = _dst_del_manifiesto(activo)
    out["asistente_ia"] = _asistente_ia_del_manifiesto(activo)

    # Ingredientes generados por IA: se informan aparte, nunca como DST del activo.
    deltas = vr.get("ingredientDeltas") if isinstance(vr, dict) else None
    out["ingredientes_ia"] = _ingredientes_ia(activo, manifests, deltas or [], uri_firmantes,
                                              vistos={activo_id} if activo_id else None)
    return out


_CLASES_IA = ("generacion", "edicion_ia")


def _dst_del_manifiesto(manifiesto: dict):
    """(digital_source_type, tipo) de las aserciones de UN manifiesto: el primer
    DST de IA (generacion/edicion) en orden; si no hay, captura, algorítmico o
    informativo, en ese orden."""
    mejor = (None, None)
    for dst in _buscar_digital_source_types(manifiesto.get("assertions") or []):
        clase = _clasificar_digital_source_type(dst)
        if clase in _CLASES_IA:
            return dst, clase
        if clase and (mejor[1] is None or
                      _PRIORIDAD_CLASE_DST[clase] < _PRIORIDAD_CLASE_DST[mejor[1]]):
            mejor = (dst, clase)
    return mejor


# Acciones con que un asistente de IA declara haber provisto el archivo, sin
# declarar el tipo de origen.
_ACCIONES_ASISTENTE_IA = {
    "com.anthropic.claude.provided": "Claude, de Anthropic",
}


def _asistente_ia_del_manifiesto(manifiesto: dict):
    """{"nombre", "accion", "confianza_origen"} de la primera acción de un
    asistente de IA conocido en las aserciones de UN manifiesto, o None."""
    for aserc in manifiesto.get("assertions") or []:
        if not (isinstance(aserc, dict) and str(aserc.get("label", "")).startswith("c2pa.actions")):
            continue
        for accion in (aserc.get("data") or {}).get("actions") or []:
            if isinstance(accion, dict) and accion.get("action") in _ACCIONES_ASISTENTE_IA:
                params = accion.get("parameters")
                params = params if isinstance(params, dict) else {}
                confianza = next((str(v) for k, v in params.items()
                                  if str(k).endswith("origin-confidence")), None)
                return {"nombre": _ACCIONES_ASISTENTE_IA[accion["action"]],
                        "accion": accion["action"], "confianza_origen": confianza}
    return None


def _estado_ingrediente(ing: dict, deltas: list, uri_firmantes):
    """Estado C2PA del manifiesto de un ingrediente: lo que se registró al
    incorporarlo (ing.validation_results) más lo que el SDK revalidó al leer
    (validation_results.ingredientDeltas, enlazado por la etiqueta de la
    aserción). Retorna (estado, invalidez); (None, None) si no hay datos de
    validación."""
    entradas = {"success": [], "informational": [], "failure": []}
    vr = ing.get("validation_results")
    if isinstance(vr, dict):
        am = vr.get("activeManifest") or {}
        for k in entradas:
            entradas[k] += [s for s in (am.get(k) or []) if isinstance(s, dict)]
    etiqueta = ing.get("label")
    for d in deltas:
        uri = (d or {}).get("ingredientAssertionURI") or ""
        if etiqueta and uri.endswith("/" + etiqueta):
            vd = d.get("validationDeltas") or {}
            for k in entradas:
                entradas[k] += [s for s in (vd.get(k) or []) if isinstance(s, dict)]
    if not any(entradas.values()):
        return None, None
    codigos = {k: [s.get("code") for s in v if s.get("code")] for k, v in entradas.items()}
    estado = _estado_c2pa(None, codigos)
    if estado == C2PA_CONFIABLE and uri_firmantes and not any(
            uri_firmantes in (s.get("explanation") or "") for s in entradas["success"]
            if s.get("code") == "signingCredential.trusted"):
        estado = C2PA_VALIDO_NO_CONFIABLE
    return estado, (_tipo_invalidez(codigos) if estado == C2PA_INVALIDO else None)


def _ingredientes_ia(manifiesto, manifests, deltas, uri_firmantes,
                     vistos=None, profundidad=0) -> list:
    """Ingredientes (directos y anidados) cuyo manifiesto declara un DST de IA.

    Cada uno: {manifiesto (etiqueta), firmante, digital_source_type, tipo,
    titulo, relacion, estado_c2pa, profundidad}."""
    vistos = set() if vistos is None else vistos
    out = []
    for ing in manifiesto.get("ingredients") or []:
        if not isinstance(ing, dict):
            continue
        etiqueta = ing.get("active_manifest")
        m = manifests.get(etiqueta) if etiqueta else None
        if not isinstance(m, dict) or etiqueta in vistos:
            continue
        vistos.add(etiqueta)
        dst, tipo = _dst_del_manifiesto(m)
        if tipo in _CLASES_IA:
            sig = m.get("signature_info") if isinstance(m.get("signature_info"), dict) else {}
            estado, invalidez = _estado_ingrediente(
                ing, deltas if profundidad == 0 else [], uri_firmantes)
            out.append({
                "manifiesto": etiqueta,
                "firmante": sig.get("issuer") or sig.get("common_name"),
                "digital_source_type": dst,
                "tipo": tipo,
                "titulo": ing.get("title"),
                "relacion": ing.get("relationship"),
                "estado_c2pa": estado,
                "invalidez": invalidez,
                "profundidad": profundidad,
            })
        if profundidad < 8:   # cota contra cadenas patológicas
            out.extend(_ingredientes_ia(m, manifests, deltas, uri_firmantes,
                                        vistos, profundidad + 1))
    return out


_NOMBRE_BIBLIOTECA_C2PA = {"win32": "c2pa_c.dll", "darwin": "libc2pa_c.dylib",
                           "linux": "libc2pa_c.so"}


# Motivo por el que c2pa no se carga en este proceso, o None.
_MOTIVO_SIN_C2PA = None


def _biblioteca_c2pa_ajena():
    """Ruta de una biblioteca nativa de c2pa en la carpeta de trabajo, en sus
    libs/ o artifacts/ o en una subcarpeta de esas tres, o None. c2pa-python
    0.38 las revisa antes que su paquete (c2pa/lib.py,
    _get_possible_search_paths) y carga la primera que encuentra: una DLL
    dejada ahí correría dentro de este proceso. Se revisan todas
    las subcarpetas, no solo las de plataforma que nombra esta versión."""
    nombres = {_NOMBRE_BIBLIOTECA_C2PA.get(sys.platform), os.environ.get("C2PA_LIBRARY_NAME")}
    nombres.discard(None)
    try:
        trabajo = os.getcwd()
    except OSError:
        return None   # sin carpeta de trabajo c2pa-python tampoco puede buscar ahí
    try:
        import importlib.util
        spec = importlib.util.find_spec("c2pa")   # no ejecuta el paquete
        propias = {os.path.normcase(os.path.realpath(os.path.join(p, "libs")))
                   for p in (spec.submodule_search_locations or [])} if spec else set()
    except Exception:
        propias = set()
    for base in (trabajo, os.path.join(trabajo, "artifacts"), os.path.join(trabajo, "libs")):
        carpetas = [base]
        try:
            carpetas += sorted(e.path for e in os.scandir(base) if e.is_dir())
        except OSError:
            pass
        for carpeta in carpetas:
            if os.path.normcase(os.path.realpath(carpeta)) in propias:
                continue
            for nombre in nombres:
                ruta = os.path.join(carpeta, nombre)
                if os.path.exists(ruta):
                    return ruta
    return None


def _importar_c2pa():
    """El módulo c2pa (c2pa-python) o None si no está o no se puede cargar sin
    riesgo: punto único, así la versión informada y la capa ejecutada no pueden
    contradecirse."""
    global _MOTIVO_SIN_C2PA
    if "c2pa" not in sys.modules:
        if _MOTIVO_SIN_C2PA is None:
            ajena = _biblioteca_c2pa_ajena()
            if ajena:
                _MOTIVO_SIN_C2PA = (f"biblioteca nativa ajena en la carpeta de trabajo ({ajena}): "
                                    "no se cargó")
        if _MOTIVO_SIN_C2PA:
            return None
    try:
        import c2pa
        return c2pa
    except Exception:
        return None


def version_c2pa_python() -> str:
    """"0.38.0 (c2pa-rs 0.91.0)" o "no disponible"."""
    c2pa = _importar_c2pa()
    if c2pa is None:
        return NO_DISPONIBLE
    version = getattr(c2pa, "__version__", None) or "versión desconocida"
    try:
        return f"{version} (c2pa-rs {c2pa.sdk_version()})"
    except Exception:
        return str(version)


def _verificar_c2pa(ruta: str):
    """Lee y valida el manifiesto C2PA con c2pa-python si está instalada.

    Retorna:
      - dict de _extraer_info_c2pa()         si hay manifiesto.
      - {"presente": False, "estado_c2pa": AUSENTE}
                                             si la librería está pero no hay manifiesto.
      - {"presente": False, "error": str}    si la librería no pudo leer el archivo
                                             (formato no soportado, archivo o
                                             manifiesto ilegible); el llamador decide
                                             si es un manifiesto malformado.
      - None                                 si la librería NO está disponible
                                             (el llamador cae a la heurística de bytes).
    Todo dict lleva "listas_confianza" (resumen_listas: SHA-256 y si se cargó).
    """
    c2pa = _importar_c2pa()
    if c2pa is None:
        return None

    contexto, listas, uri_firmantes = _contexto_c2pa(c2pa)
    out = _leer_c2pa(c2pa, ruta, contexto, uri_firmantes)
    out["listas_confianza"] = _c2pa_confianza.resumen_listas(listas)
    # Los EKU del firmante que el lector acepta cambian el resultado:
    # van en la trazabilidad. Sin Context, el SDK no recibió la configuración.
    out["eku_aceptados"] = list(_c2pa_confianza.EKU_ACEPTADOS) if contexto is not None else None
    return out


# Context de c2pa-python: se arma una vez por proceso.
_CONTEXTO_C2PA = None
_CONTEXTO_LOCK = threading.Lock()


def _contexto_c2pa(c2pa):
    """(Context o None, listas cargadas, uri de la lista de firmantes)."""
    global _CONTEXTO_C2PA
    with _CONTEXTO_LOCK:
        if _CONTEXTO_C2PA is None:
            listas = _c2pa_confianza.cargar_listas()
            contexto, con_anclas = None, False
            Context = getattr(c2pa, "Context", None)
            if Context is not None and hasattr(Context, "from_dict"):
                # Primero con las anclas; si el SDK rechaza la configuración, al
                # menos un Context offline (sin OCSP ni manifiestos remotos).
                for cfg, anclas in ((_c2pa_confianza.settings_c2pa(listas), True),
                                    (_c2pa_confianza.settings_c2pa({}), False)):
                    try:
                        contexto, con_anclas = Context.from_dict(cfg), anclas
                        break
                    except Exception:
                        contexto = None
            if not con_anclas:
                # Sin anclas cargadas nadie puede salir confiable.
                listas = {n: dict(i, cargada=False, pem=None,
                                  motivo=i.get("motivo") or "el SDK no aceptó la configuración")
                          for n, i in listas.items()}
            _CONTEXTO_C2PA = (contexto, listas, _c2pa_confianza.uri_lista_firmantes(listas))
        return _CONTEXTO_C2PA


def _reiniciar_contexto_c2pa():
    """Descarta el Context cacheado (tests o listas reemplazadas)."""
    global _CONTEXTO_C2PA
    with _CONTEXTO_LOCK:
        _CONTEXTO_C2PA = None


def _leer_c2pa(c2pa, ruta, contexto, uri_firmantes):
    import json as _json
    texto = None
    try:
        Reader = getattr(c2pa, "Reader", None)
        if Reader is not None:
            # API 0.6: Reader.from_file(path); API 0.7+/1.x: Reader(path) context-manager;
            # 0.3x+: Reader(path, context=Context) con la configuración de confianza.
            lector = None
            if contexto is not None:
                lector = Reader(ruta, context=contexto)
            elif hasattr(Reader, "from_file"):
                try:
                    lector = Reader.from_file(ruta)
                except Exception:
                    lector = None
            if lector is None:
                lector = Reader(ruta)
            try:
                texto = lector.json()
            finally:
                cerrar = getattr(lector, "close", None)
                if callable(cerrar):
                    try:
                        cerrar()
                    except Exception:
                        pass
        elif hasattr(c2pa, "read_file"):
            texto = c2pa.read_file(ruta, None)   # API 0.4-0.5
    except Exception as e:
        # c2pa-python tipa el error ("ManifestNotFound: no JUMBF data found");
        # se compara por nombre para no atarse a la jerarquía de una versión.
        if "ManifestNotFound" in type(e).__name__ or str(e).startswith("ManifestNotFound"):
            return {"presente": False, "estado_c2pa": C2PA_AUSENTE}
        # Manifiesto remoto: c2pa-python 0.38 lo lanza como C2paError base con
        # "Remote: must fetch remote manifests from url <URL>" (su subclase
        # RemoteManifest espera otro tipo de error de c2pa-rs).
        if "RemoteManifest" in type(e).__name__ or str(e).startswith(("Remote:", "RemoteManifest:")):
            url = _RE_URL.search(str(e))
            return {"presente": False, "estado_c2pa": C2PA_REMOTO,
                    "url_remota": url.group(0) if url else None}
        # El SDK no lee el formato: no dice nada del manifiesto.
        if "NotSupported" in type(e).__name__ or str(e).startswith("NotSupported"):
            return {"presente": False, "no_soportado": True}
        return {"presente": False, "error": f"{type(e).__name__}: {e}"[:300]}

    if not texto:
        return {"presente": False, "estado_c2pa": C2PA_AUSENTE}
    try:
        store = _json.loads(texto)
    except Exception as e:
        return {"presente": False, "error": f"JSON del manifiesto ilegible: {e}"[:300]}
    return _extraer_info_c2pa(store, uri_firmantes)


_RE_URL = re.compile(r"https?://[^\s\"'<>]+")


_RE_PROVENANCE_XMP = re.compile(
    rb'dcterms:provenance\s*=\s*"([^"]+)"|<dcterms:provenance>\s*([^<\s]+)\s*</dcterms:provenance>')


def _url_provenance_xmp(datos: bytes):
    """dcterms:provenance del XMP (la dirección del manifiesto remoto) o None."""
    m = _RE_PROVENANCE_XMP.search(datos or b"")
    return (m.group(1) or m.group(2)).decode("utf-8", "replace") if m else None


def _hay_jumbf_c2pa(datos: bytes) -> bool:
    """¿Hay una caja JUMBF con el almacén C2PA en los bytes? (descripción 'jumd'
    + etiqueta 'c2pa'). Distingue un manifiesto ilegible de un archivo sin C2PA."""
    return bool(datos) and b"jumd" in datos and b"c2pa" in datos


def _hallazgos_fallo_c2pa(codigos) -> list:
    """Una línea por código de fallo de integridad (los de confianza no cuentan)."""
    out = []
    for code in (codigos or {}).get("failure") or []:
        if code in _C2PA_FALLOS_DE_CONFIANZA:
            continue
        desc = _C2PA_DESCRIPCION_FALLO.get(code, "fallo de validación del manifiesto")
        out.append(f"C2PA {code}: {desc}")
    return out


# Formatos que el SDK puede no leer, reconocidos por la cabecera (no por la
# extensión). Si el SDK no declara su MIME, no se le pregunta.
_CABECERAS_MIME = ((b"BM", "image/bmp"),)
_MIME_SDK = None


def _sdk_no_lee(datos: bytes) -> bool:
    """¿La cabecera es de un formato que el SDK instalado no lee?"""
    global _MIME_SDK
    mime = next((m for cabecera, m in _CABECERAS_MIME if (datos or b"").startswith(cabecera)),
                None)
    if mime is None:
        return False
    if _MIME_SDK is None:
        c2pa = _importar_c2pa()
        try:
            _MIME_SDK = frozenset(m.lower() for m in c2pa.Reader.get_supported_mime_types())
        except Exception:
            return False   # sin la lista, se le pregunta: NotSupported no rotula nada
    return mime not in _MIME_SDK


def _inspeccionar(ruta: str):
    """(sha256, primeros bytes, ¿hay JUMBF C2PA?) sin cargar el archivo en memoria."""
    h = hashlib.sha256()
    cabecera = bytearray()
    hay_jumd = hay_c2pa = False
    cola = b""
    with open(ruta, "rb") as f:
        while True:
            bloque = f.read(_TAM_BLOQUE)
            if not bloque:
                break
            h.update(bloque)
            if len(cabecera) < _TAM_CABECERA:
                cabecera += bloque[:_TAM_CABECERA - len(cabecera)]
            ventana = cola + bloque   # una marca puede quedar partida entre bloques
            hay_jumd = hay_jumd or b"jumd" in ventana
            hay_c2pa = hay_c2pa or b"c2pa" in ventana
            cola = bloque[-3:]
    return h.hexdigest(), bytes(cabecera), hay_jumd and hay_c2pa


def verificar(ruta) -> dict:
    """Verifica el manifiesto C2PA de un archivo, sin red y sin modificarlo.

    Retorna un dict con:
      archivo, sha256 (del archivo leído), fecha_lectura_utc (el resultado depende
      de ella: una firma sin sello de tiempo confiable vence), version, c2pa_python;
      sdk_disponible (False: no se verificó, ver motivo);
      estado: AUSENTE | MALFORMADO | REMOTO | INVALIDO | VALIDO_NO_CONFIABLE |
        CONFIABLE, o None si no se pudo determinar (ver motivo; None NO significa
        que no haya manifiesto);
      etiqueta (rótulo legible del estado), invalidez (credencial | integridad),
      hallazgos (fallos de integridad o credencial, una línea por código), codigos;
      firmante, generador, digital_source_type, tipo, ingredientes_ia, asistente_ia
        (lo que el manifiesto DECLARA; si el estado es INVALIDO con invalidez
        "integridad", MALFORMADO o REMOTO no tiene respaldo de firma);
      trust_list_uri, confianza_no_atribuible, url_remota, listas_confianza,
      eku_aceptados; motivo (por qué no hay estado).
    """
    ruta = os.fspath(ruta)
    r = {
        "archivo": ruta, "sha256": None,
        "fecha_lectura_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "version": __version__, "c2pa_python": version_c2pa_python(),
        "sdk_disponible": _importar_c2pa() is not None,
        "estado": None, "etiqueta": None, "invalidez": None, "hallazgos": [], "codigos": None,
        "firmante": None, "generador": None, "digital_source_type": None, "tipo": None,
        "ingredientes_ia": [], "asistente_ia": None, "validation_state": None,
        "trust_list_uri": None, "confianza_no_atribuible": None, "url_remota": None,
        "listas_confianza": None, "eku_aceptados": None, "motivo": None,
    }
    try:
        r["sha256"], cabecera, hay_jumbf = _inspeccionar(ruta)
    except OSError as e:
        r["motivo"] = f"no se pudo leer el archivo: {e}"
        return r
    if not r["sdk_disponible"]:
        r["motivo"] = _MOTIVO_SIN_C2PA or "c2pa-python no está disponible"
        return r
    if _sdk_no_lee(cabecera):
        r["motivo"] = "formato que el SDK no lee"
        return r

    info = _verificar_c2pa(ruta)
    r["listas_confianza"] = info.get("listas_confianza")
    r["eku_aceptados"] = info.get("eku_aceptados")
    if info.get("presente"):
        for clave in ("firmante", "generador", "digital_source_type", "tipo", "ingredientes_ia",
                      "asistente_ia", "validation_state", "trust_list_uri",
                      "confianza_no_atribuible", "codigos", "invalidez"):
            r[clave] = info.get(clave)
        r["estado"] = info.get("estado_c2pa")
        r["hallazgos"] = _hallazgos_fallo_c2pa(r["codigos"])
    elif info.get("estado_c2pa") == C2PA_REMOTO:
        r["estado"] = C2PA_REMOTO
        r["url_remota"] = info.get("url_remota") or _url_provenance_xmp(cabecera)
    elif info.get("no_soportado"):
        r["motivo"] = "formato que el SDK no lee"
    elif info.get("error"):
        if hay_jumbf:
            r["estado"] = C2PA_MALFORMADO
            r["hallazgos"] = ["C2PA manifiesto malformado: no se pudo leer ni validar"]
        r["motivo"] = info["error"]
    else:
        r["estado"] = info.get("estado_c2pa")
        r["codigos"] = info.get("codigos")
    r["etiqueta"] = etiqueta_estado_c2pa(r["estado"], r["invalidez"])
    return r
