# -*- coding: utf-8 -*-
"""Línea de comandos: python -m c2pa_verificador [--json] ARCHIVO [ARCHIVO ...]

Sale con 0 si todos los archivos se pudieron leer y con 1 si alguno no.
"""

import argparse
import json
import sys

from . import __version__
from .verificador import verificar

_CAMPOS = (("Firmante declarado", "firmante"), ("Generador declarado", "generador"),
           ("DigitalSourceType declarado", "digital_source_type"),
           ("Lista de confianza", "trust_list_uri"), ("Dirección remota (no descargada)", "url_remota"),
           ("Motivo", "motivo"))


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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="c2pa-verificador",
                                     description="Verifica manifiestos C2PA sin red y sin modificar los archivos.")
    parser.add_argument("archivos", nargs="+", metavar="ARCHIVO")
    parser.add_argument("--json", action="store_true", help="salida JSON con el resultado completo")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    # Redirigida en Windows, la salida usa cp1252: un firmante con otro alfabeto
    # cortaría el programa con UnicodeEncodeError.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    resultados = [verificar(a) for a in args.archivos]
    if args.json:
        print(json.dumps(resultados, ensure_ascii=False, indent=2))
    else:
        print("\n\n".join(_texto(r) for r in resultados))
    return 1 if any(r["sha256"] is None for r in resultados) else 0


if __name__ == "__main__":
    sys.exit(main())
