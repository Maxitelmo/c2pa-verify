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


def leer_manifiesto(ruta):
    """Atajo a verificador.leer_manifiesto (importa el módulo recién al usarlo)."""
    from .verificador import leer_manifiesto as _leer_manifiesto
    return _leer_manifiesto(ruta)


def extraer_info(manifest_store, uri_firmantes=None):
    """Atajo a verificador.extraer_info (importa el módulo recién al usarlo)."""
    from .verificador import extraer_info as _extraer_info
    return _extraer_info(manifest_store, uri_firmantes)


def sdk_disponible():
    """Atajo a verificador.sdk_disponible (importa el módulo recién al usarlo)."""
    from .verificador import sdk_disponible as _sdk_disponible
    return _sdk_disponible()


def motivo_sin_sdk():
    """Atajo a verificador.motivo_sin_sdk (importa el módulo recién al usarlo)."""
    from .verificador import motivo_sin_sdk as _motivo_sin_sdk
    return _motivo_sin_sdk()


def sdk_no_lee(cabecera):
    """Atajo a verificador.sdk_no_lee (importa el módulo recién al usarlo)."""
    from .verificador import sdk_no_lee as _sdk_no_lee
    return _sdk_no_lee(cabecera)


def reiniciar():
    """Atajo a verificador.reiniciar (importa el módulo recién al usarlo)."""
    from .verificador import reiniciar as _reiniciar
    return _reiniciar()
