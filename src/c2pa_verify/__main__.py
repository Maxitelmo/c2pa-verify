# -*- coding: utf-8 -*-
"""Línea de comandos / command line: python -m c2pa_verify [--lang es|en] [--json] FILE [FILE ...]

El idioma se elige siempre de forma explícita (español por defecto) y nunca por la
configuración de la máquina: el mismo archivo da la misma salida en cualquier PC.

Sale con 0 si todos los archivos se pudieron leer y con 1 si alguno no.
"""

import argparse
import json
import sys

from . import __version__
from .english import verify
from .verificador import verificar

_CAMPOS = (("Firmante declarado", "firmante"), ("Generador declarado", "generador"),
           ("DigitalSourceType declarado", "digital_source_type"),
           ("Lista de confianza", "trust_list_uri"), ("Dirección remota (no descargada)", "url_remota"),
           ("Motivo", "motivo"))
_FIELDS = (("Declared signer", "signer"), ("Declared generator", "generator"),
           ("Declared DigitalSourceType", "digital_source_type"),
           ("Trust list", "trust_list_uri"), ("Remote address (not downloaded)", "remote_url"),
           ("Reason", "reason"))


def _texto(r: dict) -> str:
    lineas = [r["archivo"], f"  SHA-256: {r['sha256'] or 'no calculado'}",
              f"  Estado: {r['estado'] or 'no determinado'}"]
    if r["etiqueta"]:
        lineas.append(f"  Firma C2PA: {r['etiqueta']}")
    lineas += [f"  {rotulo}: {r[clave]}" for rotulo, clave in _CAMPOS if r.get(clave)]
    lineas += [f"  Hallazgo: {h}" for h in r["hallazgos"]]
    lineas += [f"  Ingrediente con IA declarada: {i['titulo'] or i['manifiesto']} "
               f"({i['firmante'] or 'firmante no informado'}, {i['estado_c2pa'] or 'sin estado'})"
               for i in r["ingredientes_ia"]]
    lineas.append(f"  Leído: {r['fecha_lectura_utc']} con c2pa-python {r['c2pa_python']}")
    return "\n".join(lineas)


def _text(r: dict) -> str:
    lines = [r["file"], f"  SHA-256: {r['sha256'] or 'not computed'}",
             f"  State: {r['state'] or 'not determined'}"]
    if r["label"]:
        lines.append(f"  C2PA signature: {r['label']}")
    lines += [f"  {label}: {r[key]}" for label, key in _FIELDS if r.get(key)]
    lines += [f"  Finding: {f}" for f in r["findings"]]
    lines += [f"  Ingredient with declared AI: {i['title'] or i['manifest']} "
              f"({i['signer'] or 'signer not reported'}, {i['state'] or 'no state'})"
              for i in r["ai_ingredients"]]
    lines.append(f"  Read: {r['read_at_utc']} with c2pa-python {r['c2pa_python']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="c2pa-verify",
        description="Verifica manifiestos C2PA sin red y sin modificar los archivos. "
                    "Verifies C2PA manifests offline, without modifying the files.")
    parser.add_argument("archivos", nargs="+", metavar="FILE")
    parser.add_argument("--json", action="store_true",
                        help="salida JSON con el resultado completo / JSON output with the full result")
    parser.add_argument("--lang", choices=("es", "en"), default="es",
                        help="idioma de la salida, español por defecto / output language, Spanish by default")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    # Redirigida en Windows, la salida usa cp1252: un firmante con otro alfabeto
    # cortaría el programa con UnicodeEncodeError.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    analizar, mostrar = (verify, _text) if args.lang == "en" else (verificar, _texto)
    resultados = [analizar(a) for a in args.archivos]
    if args.json:
        print(json.dumps(resultados, ensure_ascii=False, indent=2))
    else:
        print("\n\n".join(mostrar(r) for r in resultados))
    return 1 if any(r["sha256"] is None for r in resultados) else 0


if __name__ == "__main__":
    sys.exit(main())
