# trust/: listas de confianza C2PA

> **[English version](README.en.md)**

Anclas X.509 con las que el verificador distingue un manifiesto **válido** (íntegro, firmante desconocido) de uno
**confiable** (íntegro y con el firmante en la lista de confianza C2PA).
Sin estas listas el SDK nunca puede devolver "Trusted" (C2PA 2.2 §14.4).

Son solo certificados públicos, sin claves privadas.

## Operación offline

El verificador **no descarga nada al leer**: ni estas listas, ni OCSP, ni manifiestos
remotos. Las listas se actualizan publicando una versión nueva (ver abajo).
Una lista cuyo SHA-256 no coincide con el fijado en `listas.py` no se
carga, y entonces ningún firmante se informa como confiable.

## Fuente

- Repositorio oficial: https://github.com/c2pa-org/conformance-public
  (carpeta `trust-list/`), mantenido por C2PA Conformance.
- Commit: `a95f2c4e4be7cd015c394fc5deb188683cbbc944` (04-11-2026, "Automated
  Sync: Update trust lists").
- Integridad al bajarlas: el SHA-1 de blob de git de cada archivo coincide con
  el árbol del commit (verificado el 07-11-2026).
- Licencia: **Creative Commons Attribution 4.0 International (CC BY 4.0)**,
  texto en `LICENSE-C2PA-TRUST-LIST.txt`. Se redistribuyen sin cambios.

| Archivo | Contenido | Certificados | SHA-256 |
|---|---|---|---|
| `C2PA-TRUST-LIST.pem` | Anclas de firmantes de manifiestos | 33 | `148c1c167e98dc909a0d5793d2feee1022aa60fef5c83a0d6b08f67f4446bc37` |
| `C2PA-TSA-TRUST-LIST.pem` | Anclas de autoridades de sello de tiempo (RFC 3161) | 24 | `eca8347ee71e31d226e00c85b15aca356116fefe6c26ed8c0ee1f954115b1990` |

La *Interim Trust List* de C2PA quedó congelada el 01-01-2026; estas son las
listas vigentes del programa de conformidad.

## Cómo actualizar

1. Bajar los dos `.pem` de `trust-list/` de un commit concreto del repositorio
   oficial (no de `main` sin fijar) y verificar el SHA-1 de blob contra el árbol
   de ese commit.
2. Reemplazar los archivos acá (el `.gitattributes` del repo los mantiene en LF).
3. Actualizar `SHA256_FIJADO` en `listas.py` y la tabla de los dos README.
4. Correr la suite (`tests/test_listas.py` coteja archivo y hash fijado).

## Comportamiento verificado del SDK (c2pa-python 0.38.0, c2pa-rs 0.91.0)

- El tipo de lista `tsa` no aísla: una CA cargada solo como TSA igual valida al
  firmante del manifiesto. Por eso el verificador solo acepta "confiable" cuando
  el SDK informa que validó contra `C2PA-TRUST-LIST.pem#sha256=<hash>`.
- Hay certificados en las dos listas (Google, SSL.com). Con las dos listas
  enteras, el SDK informaba una u otra como `trustListUri` según la ejecución
  (resultado no determinista).
- El SDK evalúa la vigencia del firmante a la hora del sello de tiempo solo si
  el sello es de una TSA anclada (`timeStamp.trusted`); si no, a la hora de
  lectura, y una firma con sello válido vence igual que una sin sello.
- Por eso la lista de TSA entra al SDK **sin los certificados que comparte con la
  de firmantes**. Con esta versión:
  7 de sus 24 certificados, y el resultado lo declara en `listas_confianza`. Sin la lista de firmantes, la de TSA no se carga.
- Una clave de configuración desconocida se ignora sin error: el armado de la
  configuración tiene tests contra el SDK real.
