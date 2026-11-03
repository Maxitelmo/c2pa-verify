# Comportamiento medido del SDK

Verificado contra c2pa-python 0.38.0 (c2pa-rs 0.91.0). Al subir de versión hay que
volver a comprobarlo: `tests/test_sdk.py` corre contra el SDK real.

## Configuración

- Va en `Context.from_dict(...)`. Las claves desconocidas **se ignoran en silencio**.
- Sin `trust.trust_config`, c2pa-rs acepta solo los EKU emailProtection, timeStamping
  y OCSPSigning. documentSigning, MS C2PA signing y c2pa-kp-claimSigning dan
  `signingCredential.invalid` ("missing required EKU"), con hash y firma correctos.
  El Builder tiene el mismo hueco al firmar.

## Listas de confianza

- `trust_kind: "tsa"` **no aísla**: una CA cargada solo como TSA da "Trusted" al
  firmante de un manifiesto. Por eso `CONFIABLE` exige que `trustListUri` sea la
  lista de firmantes.
- Con certificados presentes en las dos listas, `trustListUri` alterna entre
  ejecuciones (no determinista). Por eso la lista de TSA entra sin los certificados
  que comparte con la de firmantes.
- Sin anclas, un firmante desconocido da `validation_state: "Valid"` con
  `signingCredential.untrusted` entre los fallos. `verify_trust=false` también da
  "Valid".

## Vigencia

- La vigencia del firmante se evalúa a la hora del sello de tiempo **solo si la TSA
  está anclada** (`timeStamp.trusted`); si no, a la hora de lectura. Una firma con
  sello válido de una TSA desconocida vence igual que una sin sello.

## Red

- `core.allowed_network_hosts: []` bloquea los pedidos HTTP del SDK aunque otra clave
  los habilite.
- Esa lista no alcanza a las identidades CAWG (c2pa-rs#1645), por eso
  `decode_identity_assertions` va en `False`. El lector síncrono de la FFI hoy tampoco
  las resuelve.

## Errores

| Situación | Lo que devuelve el SDK |
|---|---|
| Sin manifiesto | `ManifestNotFound` |
| Archivo roto | `Other` |
| Manifiesto remoto | `C2paError` base con `Remote: must fetch remote manifests from url <URL>`, no la subclase `RemoteManifest` |
| Formato no leído | `NotSupported` (por ejemplo BMP) |

## Carga de la biblioteca nativa

c2pa-python busca `c2pa_c` primero en la carpeta de trabajo, en `libs/` y en
`artifacts/` (y sus subcarpetas de plataforma), y recién después en su paquete. Una
biblioteca dejada ahí correría dentro del proceso; por eso no se importa `c2pa` si
aparece una.
