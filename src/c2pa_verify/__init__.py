# -*- coding: utf-8 -*-
"""Offline verification of C2PA manifests. See english.verify() and verificador.verificar()."""

__version__ = "0.2.0"


def verify(path):
    """Shortcut to english.verify (the module is imported on first use)."""
    from .english import verify as _verify
    return _verify(path)


def verificar(ruta):
    """Atajo a verificador.verificar (importa el módulo recién al usarlo)."""
    from .verificador import verificar as _verificar
    return _verificar(ruta)
