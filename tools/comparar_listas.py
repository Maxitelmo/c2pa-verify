# -*- coding: utf-8 -*-
"""Compara las listas de confianza del paquete con las de C2PA Conformance.

Solo informa: no descarga nada al paquete ni cambia ningún archivo. Actualizar
las listas es una decisión de quien mantiene el repositorio (trust/README.md).

Imprime un informe en Markdown. Sale con:
  0  las listas coinciden
  10 hay listas nuevas
  1  no se pudo comparar (nunca se informa "sin cambios" si no se pudo leer)
"""

import hashlib
import json
import os
import sys
import urllib.request

from c2pa_verify import listas

REPO = "c2pa-org/conformance-public"
CARPETA = "trust-list"
API_COMMITS = f"https://api.github.com/repos/{REPO}/commits?path={CARPETA}&per_page=1"
RAW = "https://raw.githubusercontent.com/" + REPO + "/{commit}/" + CARPETA + "/{nombre}"
SALIDA_IGUALES, SALIDA_NUEVAS, SALIDA_ERROR = 0, 10, 1
_NOMBRES = (listas.FIRMANTES, listas.TSA)


def _descargar(url: str, token=None) -> bytes:
    pedido = urllib.request.Request(url, headers={"User-Agent": "c2pa-verify-comparar-listas"})
    if token:
        pedido.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(pedido, timeout=60) as r:
        return r.read()


def _certificados(pem: bytes) -> set:
    return {der for der, _ in listas._certificados_pem(pem.decode("ascii"))}


def comparar(locales: dict, remotas: dict) -> dict:
    """{nombre: {cambio, sha256_local, sha256_remoto, agregados, quitados, total}}
    a partir de los bytes de cada lista."""
    out = {}
    for nombre in _NOMBRES:
        local, remota = locales[nombre], remotas[nombre]
        de_local, de_remota = _certificados(local), _certificados(remota)
        out[nombre] = {
            "cambio": local != remota,
            "sha256_local": hashlib.sha256(local).hexdigest(),
            "sha256_remoto": hashlib.sha256(remota).hexdigest(),
            "agregados": len(de_remota - de_local),
            "quitados": len(de_local - de_remota),
            "total": len(de_remota),
        }
    return out


def informe(resultado: dict, commit: str, fecha: str) -> str:
    lineas = [f"Fuente: [{REPO}](https://github.com/{REPO}/tree/{commit}/{CARPETA}), "
              f"commit `{commit}` ({fecha}).", "",
              "| Lista | Estado | Agregados | Quitados | Total | SHA-256 de la fuente |",
              "|---|---|---|---|---|---|"]
    for nombre, r in resultado.items():
        estado = "cambió" if r["cambio"] else "igual"
        lineas.append(f"| `{nombre}` | {estado} | {r['agregados']} | {r['quitados']} | {r['total']} "
                      f"| `{r['sha256_remoto']}` |")
    if any(r["cambio"] for r in resultado.values()):
        lineas += ["", "Quienes instalaron el paquete siguen con las listas anteriores hasta actualizar.",
                   "Para actualizar, seguir `src/c2pa_verify/trust/README.md` y publicar una versión nueva."]
    return "\n".join(lineas)


def main(descargar=_descargar) -> int:
    try:
        token = os.environ.get("GITHUB_TOKEN")
        ultimo = json.loads(descargar(API_COMMITS, token))[0]
        commit = ultimo["sha"]
        fecha = ultimo["commit"]["committer"]["date"]
        remotas = {n: descargar(RAW.format(commit=commit, nombre=n)) for n in _NOMBRES}
        locales = {}
        for nombre in _NOMBRES:
            with open(os.path.join(listas._dirs_trust()[0], nombre), "rb") as f:
                locales[nombre] = f.read()
        resultado = comparar(locales, remotas)
    except Exception as e:
        print(f"No se pudo comparar: {type(e).__name__}: {e}", file=sys.stderr)
        return SALIDA_ERROR
    print(informe(resultado, commit, fecha))
    return SALIDA_NUEVAS if any(r["cambio"] for r in resultado.values()) else SALIDA_IGUALES


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
