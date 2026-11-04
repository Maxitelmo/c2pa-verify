# c2pa-verify

Verificación **offline y determinista** de manifiestos C2PA, pensada para trabajo
forense. Informa el estado de la firma y lo que el manifiesto declara, con la
trazabilidad necesaria para reproducir el resultado.

> **[English version](https://github.com/Maxitelmo/c2pa-verify/blob/main/README.md)**

## Qué no hace

- No dice si el contenido es verdadero. Una firma confiable indica quién firmó y
  que el archivo no cambió desde entonces.
- No detecta IA. Informa lo que el manifiesto **declara**; no analiza píxeles ni
  puntúa.
- `AUSENTE` no descarta nada: la mayoría de los archivos no tiene manifiesto, y
  las plataformas de mensajería suelen quitarlo.

## Cuándo usar otra herramienta

[c2pareader](https://github.com/abrignoni/c2pareader) (MIT) lee lo que el archivo
declara, en Python puro y sin dependencias, pero no verifica firmas. Este paquete
hace el paso siguiente, verificar, a cambio de depender de c2pa-python y su
biblioteca nativa. Son complementarios: uno sirve para leer rápido en cualquier
lado, y el otro para saber si lo declarado tiene respaldo de firma.

## Instalación y uso

Requiere Python 3.10 o posterior.

```bash
pip install c2pa-verify
```

```bash
c2pa-verify foto.jpg video.mp4
```

```bash
c2pa-verify --json foto.jpg
```

```python
from c2pa_verify import verificar

r = verificar("foto.jpg")
print(r["estado"], r["etiqueta"], r["firmante"])
```

El comando está en español por defecto; con `--lang en` sale en inglés. El idioma se
elige siempre de forma explícita, nunca según la configuración de la máquina: el mismo
archivo da la misma salida en cualquier PC. En Python, `verify()` devuelve el resultado
en inglés y `verificar()` en español, a partir de la misma verificación.

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
- Instalado pesa bastante: el paquete `c2pa` de c2pa-python ocupa unos 300 MB en
  Windows.
- Las listas envejecen: quien instala queda con las de su versión hasta actualizar.
  Una tarea semanal abre un issue en este repositorio cuando la fuente cambia, pero
  actualizarlas requiere revisar y publicar una versión nueva (ver
  [trust/README.md](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/trust/README.md)).
  Para saber con qué listas se verificó, ver `listas_confianza` en el resultado.

Ver también [docs/HALLAZGOS-SDK.md](https://github.com/Maxitelmo/c2pa-verify/blob/main/docs/HALLAZGOS-SDK.md).

## Cómo verificar el método

El método está pensado para que cualquiera lo revise y lo reproduzca.

1. **Leer las reglas:** los estados salen de `_estado_c2pa`, `_tipo_invalidez` y
   `_extraer_info_c2pa`, en
   [verificador.py](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/verificador.py). La configuración del SDK está
   en `settings_c2pa`, en [listas.py](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/listas.py).
2. **Correr los tests:**

   ```bash
   git clone https://github.com/Maxitelmo/c2pa-verify.git
   ```

   ```bash
   cd c2pa-verify
   ```

   ```bash
   pip install -e .[dev]
   ```

   ```bash
   python -m pytest
   ```

   Firman sus propios archivos con una CA y una TSA descartables, contra el SDK
   real, y cubren cada estado.
3. **Cotejar las listas:** el SHA-256 de cada lista debe coincidir con el archivo
   original de [conformance-public](https://github.com/c2pa-org/conformance-public)
   en el commit indicado en
   [trust/README.md](https://github.com/Maxitelmo/c2pa-verify/blob/main/src/c2pa_verify/trust/README.md).
4. **Contrastar resultados:** lo declarado se puede comparar con c2pareader o
   c2patool. El estado de la firma solo es comparable si la otra herramienta carga
   las mismas listas y acepta los mismos EKU.

**Límite de la validación:** el repositorio no incluye imágenes reales. También se
midió sobre un banco propio de 54 archivos que no se publica porque incluye material
de terceros, así que esa medición no se puede reproducir desde acá. Los tests sí.

Si encontrás un resultado incorrecto, abrí un issue. **No subas evidencia ni archivos
de una causa:** alcanza con los códigos de `--json`, sin datos que identifiquen, o con
un archivo de prueba propio.

## Licencia

Apache-2.0 (ver [LICENSE](https://github.com/Maxitelmo/c2pa-verify/blob/main/LICENSE) y [NOTICE](https://github.com/Maxitelmo/c2pa-verify/blob/main/NOTICE)). Las listas de confianza son
de C2PA Conformance, bajo CC BY 4.0.
