# c2pa-verificador

Verificación **offline y determinista** de manifiestos C2PA, pensada para trabajo
forense. Informa el estado de la firma y lo que el manifiesto declara, con la
trazabilidad necesaria para reproducir el resultado.

*English summary: offline, deterministic C2PA manifest verification on top of
c2pa-python, with hash-pinned trust lists and separate states for "valid" and
"trusted". The API and output are in Spanish.*

## Qué no hace

- No dice si el contenido es verdadero. Una firma confiable indica quién firmó y
  que el archivo no cambió desde entonces.
- No detecta IA. Informa lo que el manifiesto **declara**; no analiza píxeles ni
  puntúa.
- `AUSENTE` no descarta nada: la mayoría de los archivos no tiene manifiesto, y
  las plataformas de mensajería suelen quitarlo.

## Instalación y uso

```bash
pip install .
```

```bash
c2pa-verificador foto.jpg video.mp4
```

```bash
c2pa-verificador --json foto.jpg
```

```python
from c2pa_verificador import verificar

r = verificar("foto.jpg")
print(r["estado"], r["etiqueta"], r["firmante"])
```

## Estados

| Estado | Significado |
|---|---|
| `CONFIABLE` | Manifiesto íntegro y firmante validado contra la lista de firmantes C2PA |
| `VALIDO_NO_CONFIABLE` | Manifiesto íntegro; el firmante no está en la lista cargada |
| `INVALIDO` + `invalidez: "credencial"` | Contenido íntegro, pero el certificado no es apto, venció o fue revocado |
| `INVALIDO` + `invalidez: "integridad"` | El contenido no coincide con el firmado, o la firma no verifica |
| `MALFORMADO` | Hay un manifiesto, pero no se puede leer |
| `REMOTO` | El archivo remite a un manifiesto en internet, que **no se descarga** (hacerlo le avisaría a quien controla esa dirección) |
| `AUSENTE` | No hay manifiesto |
| `None` | No se pudo determinar; ver `motivo`. No significa que no haya manifiesto |

## Garantías

- **Sin red:** sin OCSP, sin manifiestos remotos y con la lista de hosts vacía. Los
  tests lo comprueban con una escucha local y un control positivo.
- **Sin escrituras:** el archivo solo se lee.
- **Listas fijadas:** una lista cuyo SHA-256 no coincide con el fijado no se carga,
  y entonces nadie sale confiable.
- **Confianza atribuible:** `CONFIABLE` exige que el SDK haya validado contra la
  lista de firmantes, no contra la de sellos de tiempo.
- **Trazable:** cada resultado registra SHA-256 del archivo, fecha de lectura,
  versiones, hash de las listas y EKU aceptados.

## El resultado depende de la fecha

Una firma sin sello de tiempo de una TSA anclada se valida con la fecha de lectura:
cuando el certificado vence, el mismo archivo pasa a `INVALIDO` por credencial.
Registrá siempre `fecha_lectura_utc` junto con el resultado.

## Limitaciones conocidas

- El SDK corre dentro del proceso: un archivo que haga fallar la biblioteca nativa
  puede cerrar el programa. Para lotes no confiables, conviene aislarlo en un
  proceso hijo.
- Se detecta una biblioteca nativa ajena en la carpeta de trabajo y no se la carga,
  pero no se verifica el hash de la biblioteca efectivamente cargada.
- Las identidades CAWG no se decodifican ni se resuelven.
- Las listas envejecen: actualizarlas requiere publicar una versión nueva (ver
  [trust/README.md](src/c2pa_verificador/trust/README.md)).

Ver también [docs/HALLAZGOS-SDK.md](docs/HALLAZGOS-SDK.md).

## Desarrollo

```bash
pip install -e .[dev]
```

```bash
python -m pytest
```

Los tests firman sus propios archivos con una CA y una TSA descartables. El
repositorio no contiene imágenes reales ni evidencia.

## Licencia

Apache-2.0 (ver [LICENSE](LICENSE) y [NOTICE](NOTICE)). Las listas de confianza son
de C2PA Conformance, bajo CC BY 4.0.
