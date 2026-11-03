# -*- coding: utf-8 -*-
"""Verificación offline de manifiestos C2PA. Ver verificador.verificar()."""

__version__ = "0.1.0"


def verificar(ruta):
    """Atajo a verificador.verificar (importa el módulo recién al usarlo)."""
    from .verificador import verificar as _verificar
    return _verificar(ruta)
