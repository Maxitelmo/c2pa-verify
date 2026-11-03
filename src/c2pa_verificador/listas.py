# -*- coding: utf-8 -*-
"""Listas de confianza C2PA (trust anchors) para validar manifiestos offline.

No se descarga nada al leer: las listas viajan con el paquete en la carpeta
`trust/` (ver trust/README.md), con su SHA-256 fijado acá. Una lista que no
coincide con el hash fijado NO se carga (una instalación alterada no puede
volver "confiable" a un firmante cualquiera).

  - C2PA-TRUST-LIST.pem: anclas de los firmantes de manifiestos (C2PA §14.4).
  - C2PA-TSA-TRUST-LIST.pem: anclas de las autoridades de sello de tiempo.

Fuente oficial: https://github.com/c2pa-org/conformance-public (trust-list/).

Comportamiento verificado contra c2pa-python 0.38.0 (c2pa-rs 0.91.0):
  - La configuración va en un Context (Settings). Una clave desconocida se
    ignora en silencio: por eso el armado tiene tests contra el SDK real.
  - El tipo de lista (trust_kind "tsa") NO aísla: una CA cargada solo como TSA
    igual valida al firmante del manifiesto. Por eso el verificador exige que
    trustListUri sea la de firmantes para aceptar CONFIABLE
    (uri_lista_firmantes()).
  - Hay certificados en las DOS listas (Google, SSL.com), y con ambas listas
    enteras el SDK informaba como trustListUri una u otra según la ejecución
    (medido: 3 de 5 la de firmantes, 2 de 5 la de TSA).
  - c2pa-rs evalúa la vigencia del firmante a la hora del sello de tiempo solo
    si el sello es de una TSA anclada (timeStamp.trusted); si no, a la hora de
    lectura, y una firma con sello válido vence igual que una sin sello.
  Por eso la lista de TSA entra al SDK sin los certificados que comparte con la
  de firmantes: cada ancla tiene un solo origen y los sellos
  de las TSA de la lista quedan anclados. Medido: mismo estado y
  mismo trustListUri en todos los archivos, en 5 corridas.
"""

import hashlib
import os
import re

SUBDIR = "trust"

# Versión de c2pa-python contra la que se verificó este módulo (claves de
# configuración, trustListUri, códigos de estado). pyproject.toml la fija.
C2PA_PYTHON_VERIFICADA = "0.38.0"

FIRMANTES = "C2PA-TRUST-LIST.pem"
TSA = "C2PA-TSA-TRUST-LIST.pem"

# SHA-256 fijados (commit d6dec63 de c2pa-org/conformance-public, 26-10-2026).
# Para actualizar: reemplazar el PEM, este digest y trust/README.md.
SHA256_FIJADO = {
    FIRMANTES: "b3949271a07b007e92ef1d18050b55388f5e0d2686a16fd864176c48421af8ae",
    TSA:       "7182cb227c02701be0eebd67ab635fca7f85431c32796fb53b267c657cd2c675",
}

_KIND = {FIRMANTES: "manifest", TSA: "tsa"}

# EKU que el lector acepta en el certificado del firmante: los seis por defecto
# de c2pa-rs (sdk/src/crypto/cose/valid_eku_oids.cfg). Sin trust.trust_config,
# c2pa-rs 0.91 se queda con los tres que acepta por código (emailProtection,
# timeStamping, OCSPSigning) y rechaza documentSigning, MS C2PA signing y el
# propio EKU de firma C2PA con "certificate missing required EKU": el manifiesto
# quedaba INVALIDO con hash y firma correctos (caso real: imágenes de OpenAI).
EKU_ACEPTADOS = (
    "1.3.6.1.5.5.7.3.4",          # emailProtection
    "1.3.6.1.5.5.7.3.36",         # documentSigning
    "1.3.6.1.5.5.7.3.8",          # timeStamping
    "1.3.6.1.5.5.7.3.9",          # OCSPSigning
    "1.3.6.1.4.1.311.76.59.1.9",  # MS C2PA signing
    "1.3.6.1.4.1.62558.2.1",      # c2pa-kp-claimSigning
)

# Listas que se cargan en el SDK; la de TSA, sin los certificados que comparte
# con la de firmantes (ver docstring del módulo).
_CARGAR_EN_SDK = (FIRMANTES, TSA)

_RE_CERTIFICADO = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)


def _certificados_pem(pem: str) -> list:
    """[(base64 sin espacios, bloque PEM)] de cada certificado: el base64 es el
    DER, así que dos bloques iguales son el mismo certificado."""
    return [(re.sub(r"\s", "", m.group(1)), m.group(0)) for m in _RE_CERTIFICADO.finditer(pem)]


def _dirs_trust() -> list:
    """Carpetas donde buscar las listas (la del paquete)."""
    return [os.path.join(os.path.dirname(os.path.abspath(__file__)), SUBDIR)]


def _ubicar(nombre: str):
    for d in _dirs_trust():
        ruta = os.path.join(d, nombre)
        if os.path.isfile(ruta):
            return ruta
    return None


def uri_lista(nombre: str, sha256: str) -> str:
    """Identificador que el SDK devuelve como trustListUri: archivo + hash."""
    return f"{nombre}#sha256={sha256}"


def cargar_listas() -> dict:
    """Lee las dos listas. Retorna {nombre: info} con:
      ruta, sha256 (del archivo, o None si falta), fijado, verificada (bool: el
      hash coincide con el fijado), cargada (bool: va al SDK), pem (str, lo que
      va al SDK: la de TSA sin los certificados de la de firmantes), certificados
      (cuántos trae el archivo), certificados_en_sdk (cuántos van al SDK) y
      motivo (si no se carga).
    """
    out = {}
    for nombre in (FIRMANTES, TSA):
        info = {"ruta": None, "sha256": None, "fijado": SHA256_FIJADO[nombre],
                "verificada": False, "cargada": False, "pem": None, "motivo": None,
                "certificados": None, "certificados_en_sdk": None}
        ruta = _ubicar(nombre)
        if ruta is None:
            info["motivo"] = "archivo no encontrado"
            out[nombre] = info
            continue
        info["ruta"] = ruta
        try:
            with open(ruta, "rb") as f:
                datos = f.read()
        except OSError as e:
            info["motivo"] = f"no se pudo leer: {e}"
            out[nombre] = info
            continue
        info["sha256"] = hashlib.sha256(datos).hexdigest()
        if info["sha256"] != info["fijado"]:
            info["motivo"] = "el SHA-256 no coincide con el fijado (lista alterada o de otra versión)"
        else:
            try:
                pem = datos.decode("ascii")
                info["verificada"] = True
                info["certificados"] = len(_certificados_pem(pem))
                if nombre in _CARGAR_EN_SDK:
                    info["pem"], info["cargada"] = pem, True
                    info["certificados_en_sdk"] = info["certificados"]
            except UnicodeDecodeError:
                info["motivo"] = "el archivo no es un PEM"
        out[nombre] = info
    _tsa_sin_repetidos(out[FIRMANTES], out[TSA])
    return out


def _tsa_sin_repetidos(firmantes: dict, tsa: dict) -> None:
    """Deja en la lista de TSA solo los certificados que no están en la de
    firmantes. Sin la de firmantes no se carga: una ancla TSA sola valida
    firmantes en el SDK y nadie podría salir confiable de forma atribuible."""
    if not tsa["cargada"]:
        return
    if not firmantes["cargada"]:
        tsa.update(cargada=False, pem=None, certificados_en_sdk=0,
                   motivo="sin la lista de firmantes no se carga")
        return
    de_firmantes = {der for der, _ in _certificados_pem(firmantes["pem"])}
    propios = [bloque for der, bloque in _certificados_pem(tsa["pem"]) if der not in de_firmantes]
    tsa["certificados_en_sdk"] = len(propios)
    if propios:
        tsa["pem"] = "\n".join(propios) + "\n"
    else:
        tsa.update(cargada=False, pem=None,
                   motivo="todos sus certificados están en la lista de firmantes")


def uri_lista_firmantes(listas: dict):
    """trustListUri que debe informar el SDK para aceptar CONFIABLE, o None si
    la lista de firmantes no se cargó (entonces ningún firmante es confiable)."""
    info = (listas or {}).get(FIRMANTES) or {}
    return uri_lista(FIRMANTES, info["sha256"]) if info.get("cargada") else None


def settings_c2pa(listas: dict) -> dict:
    """Settings de c2pa-python para leer offline con las listas cargadas.

    Sin red: sin OCSP, sin bajar manifiestos remotos y con la lista de hosts
    permitidos vacía, que bloquea todo pedido HTTP del SDK aunque otra clave lo
    habilite. Las identidades CAWG (emisores did:web) no respetan esa lista
    (c2pa-rs#1645): no se decodifican. Entran la lista de firmantes y la de TSA
    sin los certificados repetidos (cargar_listas); ninguna sin la de firmantes."""
    anchors = []
    if (listas.get(FIRMANTES) or {}).get("cargada"):
        for nombre in _CARGAR_EN_SDK:
            info = listas.get(nombre) or {}
            if info.get("cargada"):
                anchors.append({
                    "trust_anchors": info["pem"],
                    "trust_uri": uri_lista(nombre, info["sha256"]),
                    "trust_kind": _KIND[nombre],
                })
    return {
        "verify": {
            "verify_trust": True,
            "verify_timestamp_trust": True,
            "ocsp_fetch": False,
            "remote_manifest_fetch": False,
        },
        "core": {"allowed_network_hosts": [], "decode_identity_assertions": False},
        "trust": {"anchors": anchors, "trust_config": "\n".join(EKU_ACEPTADOS) + "\n"},
    }


def resumen_listas(listas: dict) -> dict:
    """Para el resultado del verificador: {nombre: {sha256, verificada, cargada,
    motivo, certificados, certificados_en_sdk}}."""
    return {
        nombre: {"sha256": info.get("sha256"), "verificada": bool(info.get("verificada")),
                 "cargada": bool(info.get("cargada")), "motivo": info.get("motivo"),
                 "certificados": info.get("certificados"),
                 "certificados_en_sdk": info.get("certificados_en_sdk")}
        for nombre, info in (listas or {}).items()
    }
