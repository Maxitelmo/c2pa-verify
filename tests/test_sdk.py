# -*- coding: utf-8 -*-
"""Contra el SDK real: firma con una CA de prueba generada en el momento (sin red
salvo 127.0.0.1) y verifica lo que informa verificar(). Requiere c2pa-python."""

import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import subprocess
import sys
import time

import pytest

c2pa = pytest.importorskip("c2pa")
pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402
from PIL import Image  # noqa: E402

from _tsa_descartable import TsaDescartable  # noqa: E402
from c2pa_verificador import __main__ as cli  # noqa: E402
from c2pa_verificador import listas as conf  # noqa: E402
from c2pa_verificador import verificador as det  # noqa: E402


_DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"


def _nombre(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C2PA Prueba")])


def _uso(**kw):
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False)
    base.update(kw)
    return x509.KeyUsage(**base)


def _pki(eku=ExtendedKeyUsageOID.EMAIL_PROTECTION, vigencia=dt.timedelta(days=10)):
    """(cadena PEM del firmante, clave PEM, PEM de la CA raíz). `eku`: el único
    uso extendido del firmante; `vigencia`: desde ahora hasta que vence."""
    ahora = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_nombre = _nombre("C2PA Prueba Raiz")
    ca = (x509.CertificateBuilder().subject_name(ca_nombre).issuer_name(ca_nombre)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(ahora - dt.timedelta(days=1))
          .not_valid_after(ahora + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(_uso(key_cert_sign=True, crl_sign=True), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    hoja = (x509.CertificateBuilder().subject_name(_nombre("Firmante de prueba"))
            .issuer_name(ca_nombre).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - dt.timedelta(days=1))
            .not_valid_after(ahora + vigencia)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_uso(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)  # noqa: E731
    clave = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    return pem(hoja) + pem(ca), clave, pem(ca)


def _jpeg(color=(10, 120, 200)):
    buf = io.BytesIO()
    img = Image.new("RGB", (32, 32), color)
    exif = img.getexif()
    exif[271] = "Canon"
    exif[272] = "EOS R6"
    img.save(buf, "JPEG", exif=exif)
    return buf.getvalue()


def _firmar(pki, dst="trainedAlgorithmicMedia", generador="GeneradorIA-Prueba", contexto=None,
            extra=(), url_remota=None, tsa_url=None):
    """JPEG firmado. `extra`: aserciones además de c2pa.actions; `url_remota`:
    el manifiesto no se embebe y el archivo solo lleva su dirección; `tsa_url`:
    sello de tiempo RFC 3161 de esa autoridad."""
    cadena, clave, _ca = pki
    signer = c2pa.Signer.from_info(c2pa.C2paSignerInfo(
        b"es256", cadena, clave, tsa_url.encode() if tsa_url else None))
    builder = c2pa.Builder({
        "claim_generator_info": [{"name": generador, "version": "1.0"}],
        "title": "prueba.jpg",
        "assertions": [{"label": "c2pa.actions", "data": {"actions": [
            {"action": "c2pa.created", "digitalSourceType": _DST + dst}]}}, *extra],
    }, context=contexto)
    if url_remota:
        builder.set_no_embed()
        builder.set_remote_url(url_remota)
    dest = io.BytesIO()
    builder.sign(signer, "image/jpeg", io.BytesIO(_jpeg()), dest)
    return dest.getvalue()


def _firmar_edicion_con_ingrediente(pki, ingrediente: bytes):
    """Foto editada (sin DST propio) cuyo padre es `ingrediente`."""
    cadena, clave, _ca = pki
    signer = c2pa.Signer.from_info(c2pa.C2paSignerInfo(b"es256", cadena, clave, None))
    builder = c2pa.Builder({
        "claim_generator_info": [{"name": "EditorFotos-Prueba", "version": "2.0"}],
        "title": "editada.jpg",
        "assertions": [{"label": "c2pa.actions", "data": {"actions": [
            {"action": "c2pa.opened", "parameters": {"ingredientIds": ["ing1"]}},
            {"action": "c2pa.edited"}]}}],
    })
    builder.add_ingredient({"title": "origen_ia.jpg", "relationship": "parentOf",
                            "label": "ing1"}, "image/jpeg", io.BytesIO(ingrediente))
    dest = io.BytesIO()
    builder.sign(signer, "image/jpeg", io.BytesIO(_jpeg((200, 50, 50))), dest)
    return dest.getvalue()


def _mp4_minimo():
    """ftyp + moov(mvhd) + mdat: lo justo para que c2pa-rs lo trate como BMFF."""
    import struct

    def caja(tipo, datos):
        return struct.pack(">I", 8 + len(datos)) + tipo + datos
    mvhd = caja(b"mvhd", bytes(12) + struct.pack(">II", 1000, 0) + struct.pack(">I", 0x10000)
                + struct.pack(">H", 0x100) + bytes(70) + struct.pack(">I", 2))
    return (caja(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isommp41")
            + caja(b"moov", mvhd) + caja(b"mdat", bytes(range(256)) * 16))


def _firmar_mp4(pki):
    cadena, clave, _ca = pki
    signer = c2pa.Signer.from_info(c2pa.C2paSignerInfo(b"es256", cadena, clave, None))
    builder = c2pa.Builder({
        "claim_generator_info": [{"name": "VideoIA-Prueba", "version": "1"}],
        "title": "clip.mp4",
        "assertions": [{"label": "c2pa.actions", "data": {"actions": [
            {"action": "c2pa.created", "digitalSourceType": _DST + "trainedAlgorithmicMedia"}]}}],
    })
    dest = io.BytesIO()
    builder.sign(signer, "video/mp4", io.BytesIO(_mp4_minimo()), dest)
    return dest.getvalue()


_EKU_FIRMA_C2PA = x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")


_SEIS_EKU = "\n".join((
    "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.36", "1.3.6.1.5.5.7.3.8",
    "1.3.6.1.5.5.7.3.9", "1.3.6.1.4.1.311.76.59.1.9", "1.3.6.1.4.1.62558.2.1")) + "\n"


def _firmar_con_eku_c2pa(pki_c2pa):
    # El Builder tiene el mismo hueco que el lector: sin trust_config rechaza
    # ese EKU al firmar.
    return _firmar(pki_c2pa, contexto=c2pa.Context.from_dict({"trust": {"trust_config": _SEIS_EKU}}))


@contextlib.contextmanager
def _escucha():
    """Socket en 127.0.0.1 (puerto libre) que anota cada conexión y la cierra
    sin responder. Rinde (puerto, conexiones)."""
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    conexiones, fin = [], threading.Event()

    def aceptar():
        while not fin.is_set():
            try:
                c, origen = srv.accept()
            except OSError:   # incluye el timeout
                continue
            conexiones.append(origen)
            c.close()
    hilo = threading.Thread(target=aceptar, daemon=True)
    hilo.start()
    try:
        yield srv.getsockname()[1], conexiones
    finally:
        fin.set()
        hilo.join(2)
        srv.close()


def _cbor(v):
    """CBOR mínimo (mapas, listas, texto, bytes, enteros) para la firma COSE."""
    def cab(mayor, n):
        if n < 24:
            return bytes([mayor << 5 | n])
        for extra, largo in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * largo):
                return bytes([mayor << 5 | extra]) + n.to_bytes(largo, "big")
    if isinstance(v, int):
        return cab(0, v) if v >= 0 else cab(1, -1 - v)
    if isinstance(v, bytes):
        return cab(2, len(v)) + v
    if isinstance(v, str):
        return cab(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return cab(4, len(v)) + b"".join(_cbor(x) for x in v)
    return cab(5, len(v)) + b"".join(_cbor(k) + _cbor(x) for k, x in v.items())


def _identidad_cawg(did):
    """Aserción cawg.identity con sig_type identity_claims_aggregation: una
    credencial W3C cuyo emisor es `did`, en un COSE_Sign1 (tag 18) con firma de
    ceros. Los byte strings van como listas de enteros: el Builder arma el CBOR
    desde JSON y c2pa-rs los acepta como bytes."""
    import base64
    import json
    sig_type = "cawg.identity_claims_aggregation"
    ref = {"url": "self#jumbf=c2pa.assertions/c2pa.hash.data", "hash": list(bytes(32))}
    vc = {"@context": ["https://www.w3.org/ns/credentials/v2",
                       "https://cawg.io/identity/1.1/ica/context/"],
          "type": ["VerifiableCredential", "IdentityClaimsAggregationCredential"],
          "issuer": did, "validFrom": "2026-10-01T00:00:00Z",
          "credentialSubject": {
              "id": did + ":sujeto",
              "verifiedIdentities": [{
                  "type": "cawg.social_media", "name": "Prueba", "username": "prueba",
                  "uri": "https://example.test/prueba", "verifiedAt": "2026-10-01T00:00:00Z",
                  "provider": {"id": "https://example.test", "name": "example"}}],
              "c2paAsset": {"referenced_assertions": [
                  dict(ref, hash=base64.b64encode(bytes(32)).decode())], "sig_type": sig_type}}}
    cose = b"\xd2" + _cbor([_cbor({1: -7, 3: "application/vc"}), {}, json.dumps(vc).encode(),
                            bytes(64)])
    return {"label": "cawg.identity", "data": {
        "signer_payload": {"referenced_assertions": [ref], "sig_type": sig_type},
        "signature": list(cose), "pad1": list(bytes(16))}}


def _bmp(cola=b""):
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (40, 40, 40)).save(buf, "BMP")
    return buf.getvalue() + cola



@pytest.fixture(scope="module")
def pki():
    return _pki()


@pytest.fixture(scope="module")
def pki_eku_c2pa():
    return _pki(eku=_EKU_FIRMA_C2PA)


@pytest.fixture(autouse=True)
def contexto_limpio():
    """Cada test arma su Context (las listas pueden estar simuladas)."""
    det._reiniciar_contexto_c2pa()
    yield
    det._reiniciar_contexto_c2pa()


@pytest.fixture
def listas_prueba(tmp_path, monkeypatch):
    """Listas reemplazadas por PEM de prueba, con el hash fijado acorde."""
    d = tmp_path / "trust"
    d.mkdir()
    monkeypatch.setattr(conf, "_dirs_trust", lambda: [str(d)])
    fijado = dict(conf.SHA256_FIJADO)
    monkeypatch.setattr(conf, "SHA256_FIJADO", fijado)

    def _set(firmantes, tsa):
        for nombre, pem in ((conf.FIRMANTES, firmantes), (conf.TSA, tsa)):
            (d / nombre).write_bytes(pem)
            fijado[nombre] = hashlib.sha256(pem).hexdigest()
    return _set


@pytest.fixture
def sin_proxy(monkeypatch):
    """Que un proxy del entorno no desvíe los pedidos del SDK lejos de la escucha."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")


def _archivo(tmp_path, datos, nombre="a.jpg"):
    ruta = tmp_path / nombre
    ruta.write_bytes(datos)
    return ruta


def _esperar_vencimiento(vence):
    time.sleep(max(0.0, (vence - dt.datetime.now(dt.timezone.utc)).total_seconds()) + 1.5)


# ── Estados ──────────────────────────────────────────────────────────────────

def test_firmante_desconocido_es_valido_no_confiable(tmp_path, pki):
    r = det.verificar(_archivo(tmp_path, _firmar(pki)))
    assert r["estado"] == "VALIDO_NO_CONFIABLE"
    assert r["validation_state"] == "Valid"
    assert "signingCredential.untrusted" in r["codigos"]["failure"]
    assert r["tipo"] == "generacion" and r["generador"] == "GeneradorIA-Prueba"
    assert r["firmante"] == "C2PA Prueba"
    assert r["hallazgos"] == []
    assert "firmante fuera de la lista" in r["etiqueta"]


def test_archivo_alterado_tras_firma_es_invalido_por_integridad(tmp_path, pki):
    datos = bytearray(_firmar(pki))
    datos[-10] ^= 0xFF
    r = det.verificar(_archivo(tmp_path, bytes(datos)))
    assert r["estado"] == "INVALIDO" and r["invalidez"] == "integridad"
    assert "assertion.dataHash.mismatch" in r["codigos"]["failure"]
    assert any("dataHash.mismatch" in h for h in r["hallazgos"])


def test_jpeg_sin_manifiesto_es_ausente(tmp_path):
    r = det.verificar(_archivo(tmp_path, _jpeg()))
    assert r["estado"] == "AUSENTE" and r["etiqueta"] is None and r["motivo"] is None
    assert r["firmante"] is None


def test_xmp_sin_manifiesto_no_es_un_manifiesto(tmp_path):
    xmp = (b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta><rdf:Description "
           b'Iptc4xmpExt:DigitalSourceType="' + _DST.encode()
           + b'trainedAlgorithmicMedia"/></x:xmpmeta>')
    jpeg = _jpeg()
    datos = jpeg[:2] + b"\xff\xe1" + (len(xmp) + 2).to_bytes(2, "big") + xmp + jpeg[2:]
    r = det.verificar(_archivo(tmp_path, datos))
    assert r["estado"] == "AUSENTE" and r["digital_source_type"] is None


def test_ingrediente_de_ia_se_informa_aparte_del_activo(tmp_path, pki):
    r = det.verificar(_archivo(tmp_path, _firmar_edicion_con_ingrediente(pki, _firmar(pki))))
    assert r["tipo"] is None
    ing = r["ingredientes_ia"]
    assert len(ing) == 1
    assert ing[0]["firmante"] == "C2PA Prueba"
    assert ing[0]["digital_source_type"].endswith("trainedAlgorithmicMedia")
    assert ing[0]["estado_c2pa"] == "VALIDO_NO_CONFIABLE"


def test_video_mp4_firmado(tmp_path, pki):
    r = det.verificar(_archivo(tmp_path, _firmar_mp4(pki), "clip.mp4"))
    assert r["estado"] == "VALIDO_NO_CONFIABLE"
    assert r["tipo"] == "generacion" and r["generador"] == "VideoIA-Prueba"


def test_video_mp4_alterado_tras_firma(tmp_path, pki):
    datos = bytearray(_firmar_mp4(pki))
    datos[datos.rfind(b"mdat") + 100] ^= 0xFF
    r = det.verificar(_archivo(tmp_path, bytes(datos), "clip.mp4"))
    assert r["estado"] == "INVALIDO" and r["invalidez"] == "integridad"
    assert any("bmffHash.mismatch" in h for h in r["hallazgos"])


# ── Trazabilidad ─────────────────────────────────────────────────────────────

def test_resultado_declara_con_que_se_verifico(tmp_path, pki):
    datos = _firmar(pki)
    r = det.verificar(_archivo(tmp_path, datos))
    assert r["sha256"] == hashlib.sha256(datos).hexdigest()
    assert r["c2pa_python"].startswith(c2pa.__version__ + " (c2pa-rs ")
    assert r["fecha_lectura_utc"].endswith("+00:00")
    assert r["eku_aceptados"] == list(conf.EKU_ACEPTADOS)
    listas = r["listas_confianza"]
    for nombre in (conf.FIRMANTES, conf.TSA):
        assert listas[nombre]["verificada"] is True
        assert listas[nombre]["sha256"] == conf.SHA256_FIJADO[nombre]
    assert 0 < listas[conf.TSA]["certificados_en_sdk"] < listas[conf.TSA]["certificados"]


def test_el_sdk_instalado_es_el_verificado():
    assert c2pa.__version__ == conf.C2PA_PYTHON_VERIFICADA


def test_verificar_no_modifica_el_archivo(tmp_path, pki):
    datos = _firmar(pki)
    ruta = _archivo(tmp_path, datos)
    det.verificar(ruta)
    assert ruta.read_bytes() == datos


def test_archivo_inexistente_no_afirma_estado(tmp_path):
    r = det.verificar(tmp_path / "no_existe.jpg")
    assert r["estado"] is None and r["sha256"] is None and "no se pudo leer" in r["motivo"]


def test_sin_sdk_no_afirma_estado(tmp_path, monkeypatch):
    monkeypatch.setattr(det, "_importar_c2pa", lambda: None)
    r = det.verificar(_archivo(tmp_path, _jpeg()))
    assert r["sdk_disponible"] is False and r["estado"] is None and r["motivo"]
    assert r["sha256"]


# ── Listas de confianza ──────────────────────────────────────────────────────

def test_firmante_en_la_lista_de_firmantes_es_confiable(tmp_path, pki, listas_prueba):
    listas_prueba(firmantes=pki[2], tsa=_pki()[2])
    r = det.verificar(_archivo(tmp_path, _firmar(pki)))
    assert r["estado"] == "CONFIABLE"
    assert r["trust_list_uri"].startswith("C2PA-TRUST-LIST.pem#sha256=")


def test_firmante_encadenado_solo_a_la_lista_tsa_no_es_confiable(tmp_path, pki, listas_prueba):
    # c2pa-rs no aísla las listas por tipo: una ancla TSA valida al firmante y el
    # SDK dice "Trusted". CONFIABLE exige la lista de firmantes.
    listas_prueba(firmantes=_pki()[2], tsa=pki[2])
    r = det.verificar(_archivo(tmp_path, _firmar(pki)))
    assert r["estado"] == "VALIDO_NO_CONFIABLE"
    assert r["confianza_no_atribuible"].startswith("C2PA-TSA-TRUST-LIST.pem#sha256=")


def test_firmante_en_las_dos_listas_es_confiable_siempre(tmp_path, pki, listas_prueba):
    listas_prueba(firmantes=pki[2], tsa=pki[2])
    ruta = _archivo(tmp_path, _firmar(pki))
    for _ in range(3):
        det._reiniciar_contexto_c2pa()
        r = det.verificar(ruta)
        assert r["estado"] == "CONFIABLE"
        assert r["trust_list_uri"].startswith("C2PA-TRUST-LIST.pem#sha256=")


def test_lista_de_firmantes_alterada_no_valida_a_nadie(tmp_path, pki, listas_prueba):
    listas_prueba(firmantes=pki[2], tsa=_pki()[2])
    conf.SHA256_FIJADO[conf.FIRMANTES] = "0" * 64
    r = det.verificar(_archivo(tmp_path, _firmar(pki)))
    assert r["estado"] == "VALIDO_NO_CONFIABLE"
    assert r["listas_confianza"][conf.FIRMANTES]["cargada"] is False


# ── EKU ──────────────────────────────────────────────────────────────────────

def test_firmante_con_eku_de_firma_c2pa_es_valido_no_confiable(tmp_path, pki_eku_c2pa):
    # Sin trust_config, c2pa-rs 0.91 rechaza este EKU con "certificate missing
    # required EKU": el manifiesto quedaba INVALIDO con hash y firma correctos.
    r = det.verificar(_archivo(tmp_path, _firmar_con_eku_c2pa(pki_eku_c2pa)))
    assert r["estado"] == "VALIDO_NO_CONFIABLE" and r["invalidez"] is None
    assert "signingCredential.invalid" not in r["codigos"]["failure"]


def test_firmante_con_eku_de_firma_c2pa_y_raiz_en_la_lista_es_confiable(
        tmp_path, pki_eku_c2pa, listas_prueba):
    listas_prueba(firmantes=pki_eku_c2pa[2], tsa=_pki()[2])
    r = det.verificar(_archivo(tmp_path, _firmar_con_eku_c2pa(pki_eku_c2pa)))
    assert r["estado"] == "CONFIABLE"


# ── Credencial no aceptada con contenido íntegro (firma real) ────────────────

def _credencial_no_aceptada(r, codigo):
    assert r["estado"] == "INVALIDO" and r["invalidez"] == "credencial"
    assert "assertion.dataHash.match" in r["codigos"]["success"]
    assert "assertion.dataHash.mismatch" not in r["codigos"]["failure"]
    assert any(codigo in h for h in r["hallazgos"])
    assert "contenido íntegro" in r["etiqueta"]


def test_firma_real_con_eku_no_aceptado(tmp_path):
    privado = "1.3.6.1.4.1.99999.1"
    firmante = _pki(eku=x509.ObjectIdentifier(privado))
    contexto = c2pa.Context.from_dict({"trust": {"trust_config": _SEIS_EKU + privado + "\n"}})
    r = det.verificar(_archivo(tmp_path, _firmar(firmante, contexto=contexto)))
    _credencial_no_aceptada(r, "signingCredential.invalid")


def test_firma_real_con_certificado_vencido_al_leer(tmp_path):
    vigencia = dt.timedelta(seconds=5)
    vence = dt.datetime.now(dt.timezone.utc) + vigencia
    ruta = _archivo(tmp_path, _firmar(_pki(vigencia=vigencia)))
    _esperar_vencimiento(vence)
    _credencial_no_aceptada(det.verificar(ruta), "signingCredential.expired")


# ── Vigencia a la hora del sello de tiempo ───────────────────────────────────

def test_firmante_vencido_despues_de_un_sello_de_tsa_de_la_lista_sigue_confiable(
        tmp_path, listas_prueba, sin_proxy):
    vigencia = dt.timedelta(seconds=5)
    vence = dt.datetime.now(dt.timezone.utc) + vigencia
    firmante = _pki(vigencia=vigencia)
    with TsaDescartable() as tsa:
        datos = _firmar(firmante, tsa_url=tsa.url)
        assert tsa.pedidos == 1
    listas_prueba(firmantes=firmante[2], tsa=tsa.raiz_pem)
    ruta = _archivo(tmp_path, datos)
    _esperar_vencimiento(vence)
    r = det.verificar(ruta)
    assert "timeStamp.trusted" in r["codigos"]["success"]
    assert r["estado"] == "CONFIABLE" and r["invalidez"] is None


def test_firmante_vencido_despues_de_un_sello_de_tsa_desconocida_vence(
        tmp_path, listas_prueba, sin_proxy):
    vigencia = dt.timedelta(seconds=5)
    vence = dt.datetime.now(dt.timezone.utc) + vigencia
    firmante = _pki(vigencia=vigencia)
    with TsaDescartable() as tsa:
        datos = _firmar(firmante, tsa_url=tsa.url)
    listas_prueba(firmantes=firmante[2], tsa=_pki()[2])
    ruta = _archivo(tmp_path, datos)
    _esperar_vencimiento(vence)
    r = det.verificar(ruta)
    assert "timeStamp.trusted" not in r["codigos"]["success"]
    assert r["estado"] == "INVALIDO" and r["invalidez"] == "credencial"
    assert "signingCredential.expired" in r["codigos"]["failure"]


# ── Sin red ──────────────────────────────────────────────────────────────────

def test_lectura_sin_red_aunque_otra_clave_pida_descargar(pki, sin_proxy):
    # Con remote_manifest_fetch forzado a true, solo core.allowed_network_hosts
    # vacío impide la salida. Control positivo: sin core, el pedido llega.
    settings = conf.settings_c2pa(conf.cargar_listas())
    settings["verify"]["remote_manifest_fetch"] = True
    abiertos = {k: v for k, v in settings.items() if k != "core"}
    resultado = {}
    for nombre, cfg in (("sin core", abiertos), ("con core", settings)):
        with _escucha() as (puerto, conexiones):
            datos = _firmar(pki, url_remota=f"http://127.0.0.1:{puerto}/m.c2pa")
            with pytest.raises(Exception, match="Remote"):
                c2pa.Reader("image/jpeg", io.BytesIO(datos), context=c2pa.Context.from_dict(cfg))
        resultado[nombre] = len(conexiones)
    assert resultado["sin core"] > 0, "control positivo: la escucha no recibió el pedido"
    assert resultado["con core"] == 0


def test_identidad_cawg_con_did_web_no_abre_conexiones(tmp_path, pki, sin_proxy):
    with _escucha() as (puerto, conexiones):
        ruta = _archivo(tmp_path, _firmar(pki, extra=[_identidad_cawg(f"did:web:127.0.0.1%3A{puerto}")]))
        r = det.verificar(ruta)
    assert conexiones == []
    assert r["estado"] == "VALIDO_NO_CONFIABLE"


def test_manifiesto_remoto_se_informa_sin_descargar(tmp_path, pki, sin_proxy):
    with _escucha() as (puerto, conexiones):
        url = f"http://127.0.0.1:{puerto}/m.c2pa"
        r = det.verificar(_archivo(tmp_path, _firmar(pki, url_remota=url)))
    assert conexiones == []
    assert r["estado"] == "REMOTO" and r["url_remota"] == url
    assert r["firmante"] is None


def test_video_mp4_con_manifiesto_remoto(tmp_path, pki, sin_proxy):
    cadena, clave, _ca = pki
    url = "https://manifiestos.example.test/clip.c2pa"
    builder = c2pa.Builder({
        "claim_generator_info": [{"name": "VideoIA-Prueba", "version": "1"}],
        "title": "clip.mp4",
        "assertions": [{"label": "c2pa.actions", "data": {"actions": [
            {"action": "c2pa.created", "digitalSourceType": _DST + "trainedAlgorithmicMedia"}]}}],
    })
    builder.set_no_embed()
    builder.set_remote_url(url)
    dest = io.BytesIO()
    builder.sign(c2pa.Signer.from_info(c2pa.C2paSignerInfo(b"es256", cadena, clave, None)),
                 "video/mp4", io.BytesIO(_mp4_minimo()), dest)
    r = det.verificar(_archivo(tmp_path, dest.getvalue(), "clip.mp4"))
    assert r["estado"] == "REMOTO" and r["url_remota"] == url


# ── Malformado y formatos ────────────────────────────────────────────────────

def test_jumbf_ilegible_es_malformado(tmp_path, monkeypatch):
    monkeypatch.setattr(det, "_leer_c2pa", lambda *a: {"presente": False, "error": "Other: roto"})
    r = det.verificar(_archivo(tmp_path, _jpeg() + b"\x00jumd\x00c2pa\x00"))
    assert r["estado"] == "MALFORMADO" and r["hallazgos"] and r["motivo"] == "Other: roto"


def test_error_de_lectura_sin_jumbf_no_afirma_estado(tmp_path, monkeypatch):
    monkeypatch.setattr(det, "_leer_c2pa", lambda *a: {"presente": False, "error": "Other: roto"})
    r = det.verificar(_archivo(tmp_path, _jpeg()))
    assert r["estado"] is None and r["hallazgos"] == [] and r["motivo"] == "Other: roto"


def test_marca_jumbf_partida_entre_bloques(tmp_path, monkeypatch):
    monkeypatch.setattr(det, "_TAM_BLOQUE", 8)
    ruta = _archivo(tmp_path, b"1234567" + b"jumd" + b"123456" + b"c2pa")
    assert det._inspeccionar(str(ruta))[2] is True


def test_bmp_con_bytes_jumbf_no_es_malformado(tmp_path):
    r = det.verificar(_archivo(tmp_path, _bmp(b"\x00jumd\x00c2pa\x00"), "a.bmp"))
    assert r["estado"] is None and r["hallazgos"] == []
    assert r["motivo"] == "formato que el SDK no lee"


def test_el_formato_se_decide_por_la_cabecera_no_por_la_extension(tmp_path, pki):
    assert det.verificar(_archivo(tmp_path, _bmp(), "bmp.jpg"))["estado"] is None
    assert det.verificar(_archivo(tmp_path, _firmar(pki), "jpg.bmp"))["estado"] == "VALIDO_NO_CONFIABLE"


def test_biblioteca_ajena_en_la_carpeta_de_trabajo_se_detecta(tmp_path, monkeypatch):
    # c2pa-python busca su biblioteca nativa primero en la carpeta de trabajo.
    nombre = det._NOMBRE_BIBLIOTECA_C2PA[sys.platform]
    (tmp_path / "libs").mkdir()
    (tmp_path / "libs" / nombre).write_bytes(b"no es una biblioteca")
    monkeypatch.chdir(tmp_path)
    assert det._biblioteca_c2pa_ajena().endswith(nombre)


# ── Línea de comandos ────────────────────────────────────────────────────────

def test_cli_json(tmp_path, pki, capsys):
    ruta = _archivo(tmp_path, _firmar(pki))
    assert cli.main(["--json", str(ruta)]) == 0
    salida = json.loads(capsys.readouterr().out)
    assert salida[0]["estado"] == "VALIDO_NO_CONFIABLE"


def test_cli_texto_y_archivo_faltante(tmp_path, pki, capsys):
    ruta = _archivo(tmp_path, _firmar(pki))
    assert cli.main([str(ruta), str(tmp_path / "no_existe.jpg")]) == 1
    salida = capsys.readouterr().out
    assert "VALIDO_NO_CONFIABLE" in salida and "no se pudo leer" in salida


def test_cli_salida_utf8_con_consola_cp1252(tmp_path, monkeypatch):
    # Redirigida en Windows, la salida usa cp1252: un nombre con otro alfabeto la cortaba.
    ruta = _archivo(tmp_path, _jpeg(), "\u6f22.jpg")
    entorno = dict(os.environ, PYTHONIOENCODING="cp1252")
    salida = subprocess.run([sys.executable, "-m", "c2pa_verificador", str(ruta)], env=entorno,
                            capture_output=True)
    assert salida.returncode == 0, salida.stderr
    assert "\u6f22".encode("utf-8") in salida.stdout
