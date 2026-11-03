# -*- coding: utf-8 -*-
"""Autoridad de sello de tiempo (RFC 3161) descartable para los tests C2PA.

Raíz y certificado TSA (EKU timeStamping crítico) generados en el momento,
servidos por HTTP en 127.0.0.1 (puerto libre). Responde cada TimeStampReq con
un TimeStampToken CMS firmado ES256. El DER se arma y se lee a mano (solo
SEQUENCE, SET, INTEGER, OID, OCTET STRING, GeneralizedTime y [0] EXPLICIT):
la suite no suma dependencias. Nada sale de la máquina.
"""

import datetime as dt
import hashlib
import http.server
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ── DER mínimo ───────────────────────────────────────────────────────────────

def _largo(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, contenido):
    return bytes([tag]) + _largo(len(contenido)) + contenido


def _seq(*partes):
    return _tlv(0x30, b"".join(partes))


def _set(*partes):
    return _tlv(0x31, b"".join(sorted(partes)))      # DER: SET OF ordenado


def _entero(n):
    return _tlv(0x02, n.to_bytes((n.bit_length() + 8) // 8 or 1, "big", signed=True))


def _oid(texto):
    p = [int(x) for x in texto.split(".")]
    out = bytes([40 * p[0] + p[1]])
    for v in p[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(enc))
    return _tlv(0x06, out)


def _octetos(b):
    return _tlv(0x04, b)


def _implicito0(tlv_set):
    """Un SET OF re-etiquetado [0] IMPLICIT (certificados y atributos firmados)."""
    return b"\xa0" + tlv_set[1:]


def _leer_hijos(der):
    """(tag, tlv completo, contenido) de cada elemento de una SEQUENCE."""
    def cabecera(d, i):
        n = d[i + 1]
        if n < 0x80:
            return i + 2, n
        k = n & 0x7F
        return i + 2 + k, int.from_bytes(d[i + 2:i + 2 + k], "big")
    ini, largo = cabecera(der, 0)
    i, hijos = ini, []
    while i < ini + largo:
        c, n = cabecera(der, i)
        hijos.append((der[i], der[i:c + n], der[c:c + n]))
        i = c + n
    return hijos


_SHA256 = _seq(_oid("2.16.840.1.101.3.4.2.1"))
_ECDSA_SHA256 = _seq(_oid("1.2.840.10045.4.3.2"))
_ID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"


def _uso(**kw):
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False)
    base.update(kw)
    return x509.KeyUsage(**base)


class TsaDescartable:
    """with TsaDescartable() as tsa: tsa.url para firmar, tsa.raiz_pem para la
    lista de confianza. `hora` fija el genTime atestado (None: la hora actual)."""

    def __init__(self, hora=None):
        self.hora = hora
        self.pedidos = 0
        ahora = dt.datetime.now(dt.timezone.utc)
        raiz_key = ec.generate_private_key(ec.SECP256R1())
        raiz_nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "C2PA TSA Raiz de prueba")])
        self._raiz = (x509.CertificateBuilder().subject_name(raiz_nombre).issuer_name(raiz_nombre)
                      .public_key(raiz_key.public_key()).serial_number(x509.random_serial_number())
                      .not_valid_before(ahora - dt.timedelta(days=60))
                      .not_valid_after(ahora + dt.timedelta(days=3650))
                      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                      .add_extension(_uso(key_cert_sign=True, crl_sign=True), critical=True)
                      .add_extension(x509.SubjectKeyIdentifier.from_public_key(raiz_key.public_key()),
                                     critical=False)
                      .sign(raiz_key, hashes.SHA256()))
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._cert = (x509.CertificateBuilder()
                      .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "C2PA TSA de prueba")]))
                      .issuer_name(raiz_nombre).public_key(self._key.public_key())
                      .serial_number(x509.random_serial_number())
                      .not_valid_before(ahora - dt.timedelta(days=60))
                      .not_valid_after(ahora + dt.timedelta(days=365))
                      .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                      .add_extension(_uso(digital_signature=True), critical=True)
                      .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                                     critical=True)
                      .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()),
                                     critical=False)
                      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                          raiz_key.public_key()), critical=False)
                      .sign(raiz_key, hashes.SHA256()))
        self._srv = None

    @property
    def raiz_pem(self) -> bytes:
        return self._raiz.public_bytes(serialization.Encoding.PEM)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}/"

    def responder(self, pedido: bytes) -> bytes:
        """TimeStampResp (status granted + token) para un TimeStampReq."""
        self.pedidos += 1
        hijos = _leer_hijos(pedido)
        imprint = hijos[1][1]                          # messageImprint tal cual vino
        nonce = next((c for t, _, c in hijos[2:] if t == 0x02), None)
        hora = self.hora or dt.datetime.now(dt.timezone.utc)
        partes = [_entero(1), _oid("1.2.3.4.1"), imprint, _entero(self.pedidos),
                  _tlv(0x18, hora.strftime("%Y%m%d%H%M%SZ").encode())]
        if nonce is not None:
            partes.append(_tlv(0x02, nonce))
        tst = _seq(*partes)
        cert_der = self._cert.public_bytes(serialization.Encoding.DER)
        atributos = _set(
            _seq(_oid("1.2.840.113549.1.9.3"), _set(_oid(_ID_CT_TSTINFO))),
            _seq(_oid("1.2.840.113549.1.9.4"), _set(_octetos(hashlib.sha256(tst).digest()))),
            # signingCertificateV2 (ESS): hash SHA-256 del certificado TSA
            _seq(_oid("1.2.840.113549.1.9.16.2.47"),
                 _set(_seq(_seq(_seq(_octetos(hashlib.sha256(cert_der).digest())))))),
        )
        firma = self._key.sign(atributos, ec.ECDSA(hashes.SHA256()))
        firmante = _seq(_entero(1),
                        _seq(self._raiz.subject.public_bytes(), _entero(self._cert.serial_number)),
                        _SHA256, _implicito0(atributos), _ECDSA_SHA256, _octetos(firma))
        certificados = _implicito0(_tlv(0x31, cert_der + self._raiz.public_bytes(
            serialization.Encoding.DER)))
        signed_data = _seq(_entero(3), _set(_SHA256),
                           _seq(_oid(_ID_CT_TSTINFO), _tlv(0xA0, _octetos(tst))),
                           certificados, _set(firmante))
        token = _seq(_oid("1.2.840.113549.1.7.2"), _tlv(0xA0, signed_data))
        return _seq(_seq(_entero(0)), token)

    def __enter__(self):
        tsa = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                cuerpo = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                respuesta = tsa.responder(cuerpo)
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(respuesta)))
                self.end_headers()
                self.wfile.write(respuesta)

            def log_message(self, *a):
                pass
        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()
