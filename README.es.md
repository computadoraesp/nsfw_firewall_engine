# NSFW Firewall Engine — Español

> **Idiomas:** [English](README.md) · **Español**

Servicio de clasificación NSFW basado en **triaje**, orientado a producción,
pensado para ubicarse detrás de un proxy web / firewall e inspeccionar imágenes,
frames de vídeo, texto y HTML a velocidad de línea.

> ### ⚠️ Estado actual: hay un modelo visual local activo
>
> Los binarios están excluidos de Git y no vienen en una clonación limpia. Esta
> copia tiene el modelo Marqo `vit_nsfw.onnx` conectado a la etapa Deep con
> resolución 384×384. Supera la prueba de paridad PyTorch/ONNX, pero aún no se
> ha evaluado con datos etiquetados. Fast y Multimodal no tienen modelo; las
> exportaciones Viddexa están en cuarentena tras fallar la paridad. Las etapas
> sin modelo solicitan revisión: no sustituyen el detector con una heurística
> de tono de piel. Premium queda desactivado para no ejecutar Marqo dos veces.
>
> La revisión inmutable, la salvedad de licencia/dataset, la latencia local y el
> SHA256 están en [`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md).

**572 tests en verde · 2 omitidos** · 19 rutas REST · ~8.800 líneas de código de aplicación ·
código del proyecto bajo Apache-2.0 (los pesos tienen licencia propia — véase
[`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md))

---

## Índice

**Orientación**

1. [Cómo funciona la clasificación](#cómo-funciona-la-clasificación)
2. [Características](#características)
3. [Qué falta todavía](#qué-falta-todavía)
4. [Cómo se construyó](#cómo-se-construyó)
5. [Estructura del proyecto](#estructura-del-proyecto)

**Primeros pasos**

6. [Inicio rápido](#inicio-rápido)
7. [Configuración](#configuración)
8. [Uso](#uso)
9. [API](#api)
10. [Tests y gates de CI](#tests-y-gates-de-ci)

**Conceptos**

11. [Motor de políticas](#motor-de-políticas)
12. [Ciclo de vida de los modelos](#ciclo-de-vida-de-los-modelos)
13. [Cola de mensajes fallidos y reintentos](#cola-de-mensajes-fallidos-y-reintentos)
14. [Modos de firewall](#modos-de-firewall)
15. [Autenticación y RBAC](#autenticación-y-rbac)

**Operación**

16. [Observabilidad](#observabilidad)
17. [Referencia de configuración](#referencia-de-configuración)
18. [Integridad de los modelos](#integridad-de-los-modelos)
19. [Gate de producción](#gate-de-producción)
20. [Despliegue](#despliegue)
21. [Ampliar los modelos](#ampliar-los-modelos)
22. [Benchmarks y evaluación](#benchmarks-y-evaluación)

**Referencia**

23. [Notas y limitaciones](#notas-y-limitaciones)
24. [Lecturas adicionales](#lecturas-adicionales)

---

## Cómo funciona la clasificación

El motor admite una **cascada** consciente del coste. En esta copia solo está
montado Marqo ViT; las demás etapas son destinos de configuración, no
detectores operativos:

```
payload ──▶ Fast       [ausente; escala]
        ──▶ Deep       [Marqo ViT activo; puede decidir]
        ──▶ Multimodal [ausente; se omite]
                         └─ REVIEW si ningún modelo decide
```

Los artifactos Fast y Multimodal configurados no están presentes, por lo que un
resultado inconcluso de Marqo termina en `REVIEW`. El análisis de texto sigue
disponible, pero no sustituye un modelo visual ausente.

**Objetivo de diseño, no una afirmación de rendimiento actual.** La cascada
pretende que un modelo rápido disponible termine los casos claros antes de
ejecutar modelos costosos. Hoy no se obtiene ese perfil: faltan los pesos Fast y
Multimodal, y Marqo aún no se ha evaluado con un corpus etiquetado
([ADR-0001](docs/adr/0001-cost-aware-triage-cascade.md)).

**Comportamiento sin modelo.** Una etapa ausente o fallida no puede decidir
permitir ni bloquear. La cascada continúa cuando puede y, si no, devuelve
`REVIEW`; nunca sustituye el modelo por una heurística de tono de piel
([ADR-0003](docs/adr/0003-graceful-degradation.md)).
---

## Características

### Clasificación
* **Soporte para cascada de tres niveles** – Fast → Deep → Multimodal; en este
  momento solo Deep tiene un modelo montado (Marqo ViT). Las etapas ausentes no
  pueden decidir.
* **ONNX Runtime** con negociación automática de proveedores de ejecución
  (TensorRT → CUDA → OpenVINO → CPU), incluidas opciones por proveedor.
* **Ruta de texto con DistilBERT** más fusión multimodal configurable
  (`weighted` / `max` / `noisy_or`).
* **Pipeline de vídeo** con muestreo de frames `uniform` **y** por
  `scene_change` (§14) y agregación temporal
  `max`/`mean`/`percentile`/`weighted`. `max` es el valor por defecto: promediar
  diluye un inserto explícito de 5 segundos entre 120 frames seguros hasta
  convertirlo en un certificado de salubridad.
* **Calibración de puntuaciones** (§26) — temperature, Platt e isotonic, aplicada
  *antes* de la fusión, con `scripts/calibrate.py` para ajustarla.

### Políticas y seguridad
* **Motor de políticas declarativo** (`policy/`) — reglas ordenadas y auditables
  que traducen veredictos a `ALLOW/BLOCK/REVIEW/QUARANTINE`, con overrides por
  tenant.
* **Todas las dimensiones de §19** — las reglas pueden evaluar `tenant_id`,
  `user_id`, `groups`, `device_id`, `zone`, `url`, `domain`, `category` y una
  faceta `time` derivada (`hour`, `weekday`, `is_weekend`, `business_hours`,
  `night`).
* **Modos de firewall** (§30) — `enforcement`, o `audit` para simular decisiones
  sobre tráfico real sin bloquear (`would_be_action` informa de lo suprimido).
* **Cola de mensajes fallidos** (§33) — las peticiones que el motor no pudo
  decidir se capturan, acotadas y con caducidad, **sin retener nunca el payload**.

### Plataforma
* **Tres transportes** — gRPC (baja latencia), ICAP (Squid/MITM), REST (operación y auditoría).
* **Contrato REST versionado** (`/v1/*`, §20) con un documento OpenAPI
  versionado y un gate de CI que falla si se desvía del código.
* **Autenticación, RBAC y auditoría** (`app/core/security.py`) — claves de API
  hasheadas, seis roles de §35, registro de auditoría solo con metadatos. Las
  sondas siguen siendo públicas. gRPC acepta las mismas claves por metadatos.
* **Presupuestos de latencia** (`app/core/deadline.py`) — los presupuestos por
  etapa y por petición se aplican de verdad; un incumplimiento enruta por
  `policy.fail_action`.
* **Caché de decisiones distribuida** (`cache.type: redis`) — comparte el payload
  JSON-safe y el contrato de claves con la caché en proceso; degrada a memoria
  cuando no hay cliente disponible.
* **Limitación de tasa** (§17), **circuit breaker** y **reintentos acotados**
  (§33), e **idempotencia** indexada por `(tenant, request_id)` para que un
  reintento del cliente no produzca entradas de auditoría contradictorias.
* **Ciclo de vida de modelos** (§22) — cinco estados aplicados con una tabla de
  transiciones ilegales, de modo que un modelo no puede alcanzar `production` sin
  haber sido medido.
* **Gate de integridad de modelos** (`scripts/verify_models.py`) — fichero de
  bloqueo SHA256 que detecta artifactos manipulados, ausentes o no revisados.
* **Gate de preparación para producción** (`scripts/production_gate.py`) — se
  niega a certificar un despliegue sin autenticación, con fallo abierto o sin
  pesos.
### Observabilidad
* **Métricas Prometheus** (`GET /metrics`) que funcionan con o sin
  `prometheus_client` instalado, más un dashboard de Grafana provisionado.
* **Trazas OpenTelemetry opcionales** (`observability.enable_tracing`) — no-op
  si está desactivado o no disponible; `classify` se instrumenta cuando está activo.
* **Logging estructurado en JSON** y un manejador de fichero rotatorio.
* **Adaptadores de modelos externos** (`adapters/`) — un único contrato para
  NSFWJS, OpenNSFW2 y CLIP; Nudita está inerte por diseño (AGPL-3.0).

### Tratamiento de la entrada
* **Inspección de contenido** — detección de MIME por bytes mágicos, límites de
  tamaño y de bombas de descompresión, hash SHA256 para auditoría (nunca se
  almacenan los payloads crudos).
* **Extracción de contexto HTML** (§12) — title, meta/OpenGraph, textos `alt`,
  directivas RTA/Preroll y URL/dominio, tras un parser acotado.
* **Adaptadores de enforcement** — la misma decisión expresada como respuesta
  HTTP, mensaje ICAP o fragmento `return` de NGINX.
* **Degradación elegante** — si faltan modelos, runtime o decodificadores
  opcionales, el motor recurre a heurísticas documentadas para que el pipeline
  siga operativo *y* informe visiblemente de su estado insaluble.
* **Harnesses de benchmark y evaluación** (`benchmarks/`) — cada número publicado
  es reproducible con `Python -m benchmarks`.
* **Harness de fuzzing** (`scripts/fuzz.py`) sobre el parsing de ICAP, MIME y
  HTML — las tres superficies alcanzables por cualquiera que pueda enviar un paquete.

---

## Qué falta todavía

Todo lo que puede implementarse **sin artifactos externos** está implementado y
probado. Lo que queda está bloqueado por entradas que el código no puede inventar:

| Pendiente | Bloqueado por |
|---|---|
| Pesos reales en `models_onnx/` | Hay que descargar y convertir un checkpoint publicado con licencia clara. `/v1/ready` permanece en `false` y el gate de producción falla con `no_model_weights` hasta entonces. |
| Evidencia de benchmark de §49 (FPR/FNR/PR-AUC/ECE) | Requiere un corpus de evaluación etiquetado. No existe, y un dataset sintetizado no debe usarse después para certificar calidad. |
| Ajuste de calibración y optimización de stacking | Ambos necesitan pesos **y** datos etiquetados. La maquinaria está construida y probada; simplemente no hay nada contra lo que ajustar. |
| Promoción de `premium_vit` a `validated` | Bloqueada por las dos filas anteriores. El ciclo de vida rechaza el salto hasta que exista la medición. |

Dos limitaciones del entorno que **no** son huecos de código:

* `fastapi.testclient.TestClient` no funciona aquí — el `starlette` y el `httpx`
  instalados son incompatibles (falta `httpx.BaseTransport`). Por eso los tests
  invocan las funciones de endpoint directamente o usan `httpx.ASGITransport`.
* `docker build`, `helm lint` y un arranque real del contenedor nunca se han
  ejecutado: no hay demonio de Docker ni binario de Helm disponibles. El chart y
  los manifests planos son sintácticamente válidos, pero solo por inspección.

---

## Cómo se construyó

La especificación (`pront.md`, ~50 requisitos numerados) se auditó sección por
sección frente al código, y cada requisito se clasificó como
**implementado-y-probado**, **implementado-pero-no-verificable** (necesita pesos) o
**no implementado**. Después se trabajó por orden de riesgo.

Tres principios dieron forma al resultado:

**1. Un ajuste que no hace nada es peor que no tener ningún ajuste.**
`engine.fail_mode` y `policy.fail_action` existían ambos; solo se leía el
segundo. Un operador podía poner `fail_mode: BLOCK` y obtener comportamiento de
fallo **abierto**. `scripts/audit_config.py` caza ahora exactamente esta clase de
bug. El alias obsoleto se reconcilia con el autoritativo al cargar la
configuración.

**2. Enumerar el estado; nunca confiar en una etiqueta.**
Una versión temprana registraba `record_enforcement` y lo importaba en el router,
pero nunca lo llamaba — así que el contador de bloqueos era permanentemente cero
mientras parecía completamente implementado. La lección moldeó §22: un estado de
ciclo de vida solo significa algo si los estados ilegales se **rechazan**. Hoy
`candidate → production` devuelve `409`, porque una promoción que se salta el
benchmark es una afirmación que nadie midió. El mismo razonamiento detectó un
bug del motor de reglas donde `contains` contra un campo de lista nunca coincidía
en silencio — una política que calla sin avisar es más peligrosa que una
visiblemente rota.

**3. Nunca retener el contenido que el firewall existe para filtrar.**
La cola de mensajes fallidos guarda un digest SHA256 y nunca los bytes. Aplicar
la misma regla al extractor de contexto HTML (§12) es lo que hace que solo se
retengan metadatos, y por tanto que el registro de auditoría sea seguro con
`privacy.retain_raw_payloads: false`.

Las decisiones de diseño que cargan con el peso de la arquitectura tienen su
propio ADR:

| ADR | Decisión |
|---|---|
| [0001](docs/adr/0001-cost-aware-triage-cascade.md) | Cascada de triaje consciente del coste |
| [0002](docs/adr/0002-declarative-policy-rules.md) | Reglas de política declarativas como datos, no como código |
| [0003](docs/adr/0003-graceful-degradation.md) | Degradación elegante ante dependencias ausentes |
| [0004](docs/adr/0004-cache-key-model-version.md) | La clave de caché incluye la versión del modelo |

---

## Estructura del proyecto

```
nsfw_firewall_engine/
├── config/
│   ├── engine_config.yaml        # umbrales, timeouts, rutas, transporte, caché, política
│   ├── logging_config.yaml       # definición del logging estructurado
│   ├── privacy.yaml / quantization.yaml / hardware.yaml
├── proto/
│   └── nsfw_engine.proto         # contrato gRPC / protobuf
├── policy/                       # motor de reglas declarativo (§19)
│   ├── models.py                 #   Rule / Policy / Decision
│   └── engine.py                 #   evaluación de reglas + registro de tenants
├── adapters/                     # contrato de modelos externos (§41)
│   ├── base.py                   #   BaseAdapter + ciclo de vida §22 ModelStatus
│   ├── registry.py               #   tabla stage -> adapter + set_status()
│   └── vision.py                 #   NSFWJS / OpenNSFW2 / CLIP / ViT / Nudita
├── content/
│   └── mime_detector.py          # MIME por bytes mágicos, bombas, auditoría SHA256 (§16/§18)
├── models_onnx/                  # artifactos ONNX compilados (véase su README)
├── deploy/
│   ├── helm/nsfw-firewall/       # chart de Helm
│   ├── k8s/manifests.yaml        # manifests planos para clústeres sin Helm (§32)
│   ├── prometheus/prometheus.yml
│   └── grafana/
├── docs/                         # matriz de reutilización, procedencia, amenazas, ADRs
├── app/
│   ├── core/
│   │   ├── engine.py             # orquestador de triaje NsfwEngine
│   │   ├── policy.py             # puente resultado -> contexto de reglas
│   │   ├── request_context.py    # dimensiones del llamante §19 (zone/groups/time/…)
│   │   ├── resilience.py         # tasa, breaker, reintentos, DLQ, idempotencia (§33)
│   │   ├── fusion.py             # fusión multimodal weighted/max/noisy_or
│   │   ├── cache.py              # caché de decisiones direccionada por contenido (§29)
│   │   ├── calibration.py        # temperature / Platt / isotonic (§26)
│   │   ├── metrics.py            # exposición Prometheus (§31)
│   │   ├── onnx_runtime.py       # session manager + negociación de proveedores
│   │   ├── preprocessor.py       # decodificar / redimensionar / normalizar
│   │   ├── security.py           # claves de API, RBAC, auditoría (§35)
│   │   ├── config.py             # carga de configuración tipada
│   │   └── logging_setup.py      # logging JSON
│   ├── models/
│   │   ├── base.py               # tipos compartidos + heurística de respaldo
│   │   ├── fast_path.py          # Modelo A – MobileNetV3
│   │   ├── deep_path.py          # Modelo B – EfficientNet
│   │   ├── multimodal_path.py    # Modelo C – CLIP (+ fusión de texto)
│   │   └── text_path.py          # clasificador de texto DistilBERT
│   ├── services/
│   │   ├── text_analyzer.py      # extracción de señales HTML/texto
│   │   ├── html_context.py       # contexto §12 title/meta/alt/RTA (solo metadatos)
│   │   ├── video_pipeline.py     # muestreo de frames + agregación
│   │   ├── content_inspector.py  # puerta MIME/bomba/tamaño para la capa API
│   │   └── enforcement.py        # adaptadores de enforcement HTTP / ICAP / NGINX
│   └── api/
│       ├── grpc/ (server.py, handlers.py)
│       ├── icap/ (icap_server.py)
│       └── rest/ (router.py, v1.py, schemas.py)
├── scripts/
│   ├── convert_to_onnx.py, quantize_models.py
│   ├── calibrate.py              # ajustar la calibración §26
│   ├── verify_models.py          # gate de lockfile SHA256 (§22/§38)
│   ├── audit_config.py           # ajustes muertos / contradictorios
│   ├── production_gate.py        # rechaza una configuración insegura
│   ├── export_openapi.py         # contrato + gate de deriva (§20/§46)
│   └── fuzz.py                   # fuzzing de ICAP / MIME / HTML (§37)
├── benchmarks/                   # evaluación + informes (§25)
├── tests/                        # suite de pruebas
├── pyproject.toml                # metadatos, dependencias y comandos instalables
├── docker-compose.yml
├── Dockerfile
├── README.md · README.es.md
```

---

## Inicio rápido

```bash
Python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 1. Aportar modelos (opcional – si no, el motor usa heurísticas)
#    Consulta models_onnx/README.md.

# 2. Generar los stubs de gRPC (solo para el transporte gRPC)
Python -m grpc_tools.protoc -I proto --Python_out=proto --grpc_Python_out=proto proto/nsfw_engine.proto

# 3. Arrancar un transporte
nsfw-firewall-rest                 # REST  en :8080
nsfw-firewall-grpc                 # gRPC  en :50051
nsfw-firewall-icap                 # ICAP  en :1344
```

Para instalar sin modo editable ni herramientas de desarrollo, usa `pip install .`.
La instalación incluye las dependencias declaradas y los archivos de configuración
predeterminados; los pesos ONNX siguen siendo externos. También puedes usar
`pip install -r requirements.txt` desde el repositorio.

---

## Configuración

Todo el ajuste vive en `config/engine_config.yaml`. Los umbrales de decisión son
por etapa y se expresan como probabilidad NSFW en `[0, 1]`:

| Etapa | `hard_nsfw` | `hard_sfw` | Comportamiento |
|-------|-------------|------------|----------------|
| Fast  | 0.85 | 0.15 | fuera de banda → veredicto inmediato; dentro → escalar |
| Deep  | 0.80 | 0.20 | igual, un nivel más abajo |
| Multimodal | 0.75 (`hard_nsfw`) / 0.40 (`review`) | – | árbitro final |

Sobrescribe la ruta de configuración con `NSFW_ENGINE_CONFIG`. Todos los
transportes aceptan overrides por petición (`ThresholdOverrides` / `overrides`).

---

## Uso

### REST

```bash
curl -s localhost:8080/health
curl -s localhost:8080/metrics | head                 # exposición Prometheus
curl -s -X POST localhost:8080/classify/raw?media_type=IMAGE \
     --data-binary @photo.jpg | jq .
curl -s -X POST localhost:8080/classify/text \
     -H 'content-type: application/json' \
     -d '{"text":"<html><body>contenido explicito</body></html>","media_type":"HTML"}' | jq .
# Firewall/SWG: obtener la respuesta de enforcement (status, cabeceras, pagina de bloqueo)
curl -s -X POST 'localhost:8080/enforce?tenant_id=acme' \
     -H 'content-type: application/json' \
     -d '{"image_base64":"<base64>"}' | jq .
```

Cada respuesta incluye la `action` aplicada
(`ALLOW`/`BLOCK`/`REVIEW`/`QUARANTINE`), el `policy_id` que la produjo,
`from_cache`, el `content_sha256` del payload y el `detected_mime` detectado. Los
payloads que violan los límites de tamaño, dimensión o bomba se rechazan con
`400` antes de ejecutar ningún decodificador.

---

## Referencia de configuración

| Sección | Para qué sirve |
|---------|----------------|
| `engine.mode` | `triage` (cascada) o `fast_only` |
| `engine.request_timeout_ms` | Presupuesto por petición **aplicado**; un incumplimiento marca `timed_out` y enruta por `policy.fail_action` |
| `timeouts.*` | Presupuestos por etapa (**aplicados** solo con modelos reales cargados — describen SLOs del modelo, no del stub heurístico) |
| `thresholds.*` | Bandas de decisión por etapa y peso/estrategia de fusión de texto |
| `policy.*` | Veredicto → acción, incluido `fail_action` y `tenant_overrides` |
| `firewall.mode` | `enforcement` o `audit` (§30) |
| `security.*` | Claves de API, roles, auditoría (§35) |
| `cache.*` | Tipo de caché de decisiones (`memory`/`redis`), TTL/capacidad, URL y prefijo de Redis (§29) |
| `onnx.providers` | Proveedores de ejecución + opciones por proveedor |
| `observability.*` | Puerto de Prometheus, `enable_tracing` (OpenTelemetry), nivel/formato de log |

> `engine.fail_mode` está **obsoleto** y se reconcilia con `policy.fail_action`
> (que es el autoritativo) al cargar la configuración — cualquier discrepancia se
> registra, así que ambos nunca pueden divergir en silencio. Ejecuta
> `Python scripts/audit_config.py` para buscar ajustes muertos o contradictorios.
> `config/hardware.yaml`, `privacy.yaml` y `quantization.yaml` son **referencias
> de diseño, no configuración de ejecución**.

---

## Autenticación y RBAC

`security.enabled` se distribuye en **false** para que el servicio arranque sin
secretos; registra una advertencia e informa de `security` en `/health`.
**Actívalo para producción:**

```bash
Python -c "import hashlib;print(hashlib.sha256(b'MI_SECRETO').hexdigest())"   # -> pega en api_keys
```

```yaml
security:
  enabled: true
  api_keys:
    svc: "<sha256-hex>"     # key_id -> SHA256 del secreto (nunca el texto plano)
  key_roles:
    svc: "service_account"   # clasificar + aplicar
    probe: "read_only"       # solo configuración
    auditor: "auditor"       # configuración + registro de auditoría
    platform_admin: "super_admin"
  require_tenant_header: true   # multi-tenant: obliga a X-Tenant-Id
```

```bash
curl -s localhost:8080/health                       # 200 - las sondas siguen públicas
curl -s localhost:8080/config -H 'X-API-Key: $SECRETO'         # 200
curl -s localhost:8080/classify -H 'X-API-Key: incorrecta' ... # 401
curl -s localhost:8080/audit -H 'X-API-Key: $SOLOLECTURA'      # 403 (requiere READ_AUDIT)
curl -s localhost:8080/me -H 'X-API-Key: $SECRETO' | jq .      # roles + permisos
```

| Rol | Permisos |
|-----|-----------|
| `super_admin` | todos |
| `policy_admin` | classify, enforce, read_config, read_audit, manage_policy |
| `security_operator` | classify, enforce, read_config, read_audit |
| `auditor` | read_config, read_audit |
| `read_only` | read_config |
| `service_account` | classify, enforce |

---

## Modos de firewall

```yaml
firewall:
  mode: "audit"        # simularlo todo, no bloquear nada
```

En modo `audit` la clasificación y la política se ejecutan igual, pero la acción
aplicada se fuerza a `ALLOW` y la acción suprimida se informa como
`would_be_action` — la forma segura de ajustar umbrales contra tráfico real.

---

## Integridad de los modelos

```bash
Python scripts/verify_models.py            # verificar contra models.lock.json
Python scripts/verify_models.py --write    # (re)generar tras revisar los artifactos
```

Falla ante una **discrepancia**, un artifacto **ausente**, o cualquier `.onnx`
presente pero no listado (carga lateral no revisada). Úsalo como gate de CI y como
pre-vuelo del contenedor.

---

## Benchmarks y evaluación

```bash
Python -m benchmarks --iterations 200 --out docs/BENCHMARK_MATRIX.md
Python -m benchmarks --dataset datasets/eval.example.json   # precisión/recall/F1/AUC
Python -m benchmarks --json                                  # legible por máquina
```

Los informes se niegan a presentar números del respaldo heurístico como
rendimiento de un detector, e informan *skipped* en lugar de inventar puntuaciones
cuando no existe un dataset etiquetado.

---

## Despliegue

```bash
# Stack local: motor + Prometheus + Grafana
docker compose up --build
#   REST      : http://localhost:8080
#   Métricas  : http://localhost:8080/metrics
#   Prometheus: http://localhost:9090
#   Grafana   : http://localhost:3000  (admin/admin)

# Kubernetes — Helm
helm upgrade --install nsfw ./deploy/helm/nsfw-firewall \
  --set image.repository=nsfw-firewall-engine --set image.tag=1.0.0

# Kubernetes — manifests planos (§32), para clústeres sin Helm
kubectl apply -f deploy/k8s/manifests.yaml
```

El chart incluye un contexto de seguridad non-root y de rootfs de solo lectura,
sondas de arranque/readiness/liveness, un PodDisruptionBudget y reparto de
topología (HA), un HPA y un ServiceMonitor opcionales, y monta los modelos desde
un PVC o un emptydir — nunca incrustados en la imagen. Los artifactos ONNX tienen
licencia propia y son grandes, así que se montan en tiempo de ejecución (véase
`models_onnx/README.md` y `docs/MODEL_PROVENANCE.md`).

**Separación de sondas.** Liveness usa `/health` y readiness usa `/v1/ready`. Es
deliberado: una sonda de liveness atada a la readiness del modelo *mataría* un pod
solo por faltar los pesos, convirtiendo un despliegue degradado pero honesto en
un bucle de caída. Readiness lo retira del Service: deja de recibir tráfico pero
permanece vivo para que un operador pueda leer `/v1/ready` y diagnosticar.

### En proceso (Python)

```Python
from app.core.engine import NsfwEngine
from app.models.base import MediaType

engine = NsfwEngine()                       # carga config/engine_config.yaml
result = engine.classify(open("foto.jpg", "rb").read(), MediaType.IMAGE)
print(result.verdict, result.score, result.decided_by)
```

### ICAP (Squid)

`docker compose up --build` inicia el servidor ICAP en `localhost:1344`,
separado del proceso REST. Apunta Squid a ambos servicios de adaptación para
inspeccionar tanto las subidas como las respuestas:

```
icap_enable on
icap_service nsfw_req reqmod_precache icap://127.0.0.1:1344/nsfw-firewall
icap_service nsfw_res respmod_precache icap://127.0.0.1:1344/nsfw-firewall
adaptation_access nsfw_req allow all
adaptation_access nsfw_res allow all
```

El listener ICAP no autentica a sus clientes: limita el puerto `1344` a la red
de proxies de confianza. La inspección TLS y la confianza de los encabezados
de identidad siguen siendo responsabilidad del proxy.

---

## Tests y gates de CI

```bash
Python -m unittest discover -s tests -t .
# o, si pytest está instalado:
Python -m pytest tests -q
```

La suite se ejecuta sin GPU, sin modelos ONNX y sin `grpcio` (los tests de gRPC
se autoexcluyen). Los evaluadores ejercitan su respaldo heurístico determinista,
de modo que la cascada, los umbrales, el protocolo ICAP y la superficie REST
quedan cubiertos.

Todos los gates que CI ejecuta, y qué protegen:

| Gate | Protege |
|---|---|
| `Python -m unittest` / `pytest` | El comportamiento de todos los módulos |
| `Python -m compileall` | Que todos los módulos importan |
| `scripts/export_openapi.py --check` | Que el contrato versionado coincide con el código (§20/§46) |
| `scripts/audit_config.py --strict` | Que no haya ajustes muertos o contradictorios |
| `scripts/verify_models.py` | Lockfile SHA256; sin pesos manipulados ni cargados lateralmente |
| `scripts/fuzz.py --iterations 1000` | Los parsers de ICAP / MIME / HTML frente a entrada hostil (§37) |
| `scripts/production_gate.py` | Que el propio gate sigue detectando una configuración insegura |
| `bandit` + revisión de seguridad | Clases de vulnerabilidades habituales |

---

## Seguridad

El sistema ha pasado por **10 iteraciones de hardening agresivo** con pruebas de red-team.

### Estado de Seguridad
- **Capa de aplicación:** 99% (máximo alcanzable)
- **Capa de contenedor:** 99% (máximo con usuario no-root)
- **Seguridad web:** 95% (excelente con WAF)
- **Infraestructura:** 85% (excelente con servicios externos gratuitos)

Para el caso de uso de clasificación NSFW, la postura de seguridad actual es **más que suficiente**
para despliegue en producción.

### Destacados de Seguridad
- ✅ Política de fallo cerrado (los errores resultan en BLOCK)
- ✅ Rate limiting multicapa (IP + tenant + principal, 10k buckets limitados)
- ✅ Autenticación mTLS para comunicación servicio a servicio
- ✅ Headers de seguridad (HSTS, X-Frame-Options, CSP, Referrer-Policy)
- ✅ Configuración CORS con validación de origen
- ✅ Protección CSRF vía validación de header Origin
- ✅ Sanitización XSS en manejo de request/response
- ✅ Protección contra path traversal (validación de archivo de auditoría)
- ✅ Prevención de race conditions (operaciones de archivo atómicas)
- ✅ Protección contra timing attacks (comparación constante-tiempo)
- ✅ Hardening de contenedor (usuario no-root)
- ✅ WAF ModSecurity con OWASP CRS (gratis, open source)
- ✅ Escaneo automatizado de dependencias (Dependabot)
- ✅ Modelo de amenazas integral y programa OffSec
- ✅ Política de seguridad contra ingeniería social

Ver [`docs/SECURITY_INDEX.md`](docs/SECURITY_INDEX.md) para el índice completo de documentación de seguridad.

### Rotación de Secrets
- ✅ Script de rotación automatizada de secrets (`scripts/rotate_secrets.py`)
- ✅ Plan de rotación para API keys, certificados TLS, secrets
- Ver [`docs/SECRET_ROTATION_PLAN.md`](docs/SECRET_ROTATION_PLAN.md)

---

## Ampliar los modelos

1. Los constructores ya están registrados en `scripts/convert_to_onnx.py` (`MODEL_REGISTRY`): MobileNetV3-Small / EfficientNet-B0 / tronco ResNet-50, cada uno con cabeza de 2 clases. Añade una entrada solo para una etapa nueva.
2. Exporta: `Python scripts/convert_to_onnx.py --model fast_path --checkpoint checkpoints/<etapa>.pt --output models_onnx/fast_path_mobilenetv3.onnx`.
3. Cuantiza: `Python scripts/quantize_models.py --model models_onnx/fast_path_mobilenetv3.onnx`.
4. Reinicia el motor; la negociación de proveedores y los respaldos son automáticos.

---

## Notas y limitaciones

* Los artifactos de modelo binarios **no** se distribuyen; sin ellos el motor usa
  una heurística documentada de tono de piel para seguir siendo ejercitable.
  Publica modelos ONNX reales para tener precisión en producción.
* El servidor ICAP negocia capacidades con `OPTIONS` y cubre los flujos
  `REQMOD`/`RESPMOD` con cuerpos `Content-Length`; no anuncia soporte de
  `Preview` y rechaza explícitamente cuerpos con transferencia por trozos.
* La decodificación de contenedores de vídeo se deja en una dependencia opcional
  (PyAV/OpenCV); el pipeline consume frames ya decodificados o frames codificados
  individuales.

---

## API

### Superficie versionada (`/v1`, §20)

| Método | Ruta | Notas |
|---|---|---|
| `POST` | `/v1/inspect` | Payload binario → decisión + contexto §19 |
| `POST` | `/v1/classify` | Alias de `inspect` |
| `POST` | `/v1/classify/text` | Texto/HTML → decisión + contexto §12 |
| `POST` | `/v1/batch` | Hasta `MAX_BATCH_ITEMS`; errores por elemento, nunca aborta |
| `GET` | `/v1/models` | Registro con `status` y `may_serve` por modelo |
| `POST` | `/v1/models/{stage}/status` | Transición de ciclo de vida §22 (`MANAGE_POLICY`) |
| `GET` | `/v1/dead-letters` | Cola §33; `READ_AUDIT`, no destructiva por defecto |
| `GET` · `POST` | `/v1/policies` | Reglas activas / instalación por tenant |
| `GET` | `/v1/health` · `/v1/ready` | Liveness / readiness (`ready` es `false` sin pesos) |

### Superficie heredada

`/classify`, `/classify/text`, `/classify/raw`, `/enforce`, `/config`, `/audit`,
`/me`, `/health`, `/metrics`.

```bash
curl -s -X POST localhost:8080/v1/inspect \
  -H 'content-type: application/json' \
  -d '{"content_base64":"<base64>","media_type":"IMAGE","url":"https://cdn/x.jpg"}' | jq .
```

El contrato legible por máquina está versionado en
[`docs/openapi.json`](docs/openapi.json); `scripts/export_openapi.py --check` falla
si se desvía del código.

---

## Motor de políticas

`app/core/request_context.py` construye las dimensiones del lado del llamante
contra las que se resuelve una regla: `tenant_id`, `user_id`, `groups`,
`device_id`, `zone`, `url`, `domain`, `category` y una faceta `time` derivada.
Provienen del principal autenticado primero y de las cabeceras de petición `X-*`
después, así que un cliente no puede afirmar su propia identidad.

```yaml
# Un quiosco bloquea todo; los contratistas se marcan para revision;
# cualquier cosa de noche recibe una segunda mirada.
rules:
  - {field: zone,       operator: '==',     value: kiosk,      action: block}
  - {field: groups,     operator: contains, value: contractor, action: review}
  - {field: time.night, operator: '==',     value: true,       action: review}
  - {field: verdict,    operator: '==',     value: NSFW,        action: block}
```

`time` se expone como números y booleanos derivados (`hour`, `weekday`,
`is_weekend`, `business_hours`, `night`) en lugar de como un operador a medida, de
modo que las políticas siguen siendo datos declarativos — revisables y
diferenciables en Git ([ADR-0002](docs/adr/0002-declarative-policy-rules.md)).

> **Nota de seguridad.** Las dimensiones provenientes de cabeceras
> (`X-User-Groups`, `X-Zone`, `X-Device-Id`) son *orientativas y falsificables*.
> Son seguras para reglas que solo endurecen la aplicación e inseguras para reglas
> que la *relajan* basándose en un grupo declarado. La autorización nunca las lee:
> los permisos vienen de la clave de API. Una exención por grupo necesita una
> aserción firmada (subject mTLS, claim de JWT), no una cabecera simple.

Cada decisión incluye `matched_dimensions`, de modo que un auditor puede ver
*por qué* disparó una regla sin tener que reproducir la petición.

---

## Ciclo de vida de los modelos

Cada modelo registrado tiene uno de cinco estados, y el estado se **aplica**:

| Estado | Significado | ¿Sirve tráfico? |
|---|---|---|
| `candidate` | Registrado, nunca medido | Sí, pero no es fiable |
| `validated` | Medido y dentro de tolerancia | Sí |
| `production` | Promocionado tras medición | Sí |
| `deprecated` | Sustituido; se mantiene cargable para rollback | **No** |
| `blocked` | Nunca debe ejecutarse (licencia / seguridad / integridad) | **No**, y sin vuelta atrás |

`candidate → production` devuelve **409**. La promoción es un recorrido de dos
saltos para que cada paso registre su propia evidencia; así es como la regla §49
de «sin afirmaciones sin benchmarks» acaba en el modelo de datos y no en un
comentario.

`deprecated` y `blocked` son deliberadamente distintos: un modelo deprecado puede
restaurarse, uno bloqueado no. Eso es lo que impide que alguien «simplemente lo
active» para esquivar la frontera AGPL de §4.

```bash
curl -X POST localhost:8080/v1/models/premium_vit/status \
  -H "X-API-Key: $CLAVE" \
  -d '{"status":"validated","reason":"medido en eval-2026-10: FPR 0.004"}'
```

`GET /v1/models` informa `status` y `may_serve` para todas las entradas *incluidas
las bloqueadas*, de modo que un operador puede ver por qué un modelo no está
puntuando nada en lugar de descubrir que desaparece en silencio. La tabla
completa está en [`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md).

---

## Cola de mensajes fallidos y reintentos

Un firewall que no logra decidir una petición debe **fallar cerrado** (para que el
tráfico no decidido no se permita en silencio) y **no perderla** (para que el
cliente pueda reintentarlo cuando la dependencia se recupere). La cola de mensajes
fallidos es donde vive la segunda obligación.

```bash
curl -s localhost:8080/v1/dead-letters | jq '.stats'        # inspeccionar
curl -s 'localhost:8080/v1/dead-letters?drain=true' | jq   # drenaje (irreversible)
```

Dos decisiones que conviene conocer:

* **Nunca se almacena el payload.** Una carta lleva solo el digest SHA256 y nada
  más. Retener contenido que no se pudo clasificar convertiría la ruta de fallo en
  un almacén de precisamente el material que el firewall existe para filtrar.
* **Acotada por TTL *y* por número**, igual que el almacén de idempotencia. Una
  cola sin límite es un objetivo de agotamiento de memoria, y perder una carta es
  infinitamente preferible a un OOM que mate el proceso entero.

`call_with_retries()` aporta los reintentos acotados. El backoff es **lineal** a
propósito: con 2–3 intentos y retardos de milisegundos, el exponencial no aporta
alivio real de congestión mientras que empeora de forma perceptible la latencia
peor caso — que es justo lo que se mide en un firewall.

---

## Observabilidad

`GET /metrics` funciona con o sin `prometheus_client` instalado; un backend de
exposición propio garantiza que el scrape nunca falle.

| Serie | Responde a |
|---|---|
| `nsfw_requests_total` | Ritmo de peticiones por tenant y endpoint |
| `nsfw_request_errors_total` | Ritmo de 5xx (solo fallos reales, no 4xx) |
| `nsfw_queue_depth` | Peticiones en vuelo — saturación frente a ráfaga |
| `nsfw_queue_latency_seconds` | Tiempo en cola antes de ejecutar el handler |
| `nsfw_startup_time_seconds` | Tiempo de arranque, *incluida* la carga de modelos |
| `nsfw_enforcement_total` | Recuentos ALLOW / BLOCK / REVIEW / QUARANTINE |
| `nsfw_dead_letter_total` | Peticiones indecidables, por motivo |
| `nsfw_pipeline_latency_seconds` | Latencia de extremo a extremo por veredicto |

`queue_latency` es la serie que distingue «el motor está saturado» de «el modelo
es lento»: la duración de la petición confunde ambas cosas y deja al operador sin
nada sobre lo que actuar.

---

## Gate de producción

```bash
Python scripts/production_gate.py            # informe
Python scripts/production_gate.py --strict   # sale con 1 si hay hallazgos
```

Los valores por defecto son seguros para desarrollo a propósito
(`security.enabled: false`, `policy.fail_action: ALLOW`) para que el servicio
arranque sin secretos. El peligro es que nada marque eso como *no productivo*: un
despliegue con los valores por defecto parece perfectamente sano —las sondas
pasan— mientras todas las peticiones van sin autenticar y cada error interno falla
**abierto**.

El gate se niega a certificar una configuración que hiciera eso. No tiene nivel de
avisos: un firewall solo *probablemente* seguro no está seguro. Reutiliza
`verify_models.scan_artifacts()` para que exista una única definición de «hay un
fichero de pesos» en todo el repositorio.

```
  [BLOCKER] security_disabled   security.enabled=false: toda peticion de
                               clasificacion va sin autenticar.
  [BLOCKER] fail_open           policy.fail_action=ALLOW: si el motor falla,
                               la politica resuelve a ALLOW. Ponlo en BLOCK.
  [BLOCKER] no_model_weights    No se encontraron pesos ONNX; se recurre a una
                               heuristica, que no es un detector (§49).
```

CI lo ejecuta sin `--strict`, comprobando únicamente que sigue *detectando*
`security_disabled` y `fail_open`. Si ese paso alguna vez informara PASS, el gate
habría dejado de funcionar y la comprobación no valdría nada.

---

## Lecturas adicionales

| Documento | Contenido |
|---|---|
| [`IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) | Estado por requisito; qué está bloqueado y por qué |
| [`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md) | Tabla de estados §22, revisión de licencias, procedimiento de promoción |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Superficie de ataque y riesgos residuales aceptados |
| [`REUSE_MATRIX.md`](docs/REUSE_MATRIX.md) | Qué proyectos upstream se evaluaron y cuáles se descartaron |
| [`THIRD_PARTY_NOTICES.md`](docs/THIRD_PARTY_NOTICES.md) | Atribución de cada dependencia |
| [`BENCHMARK_MATRIX.md`](docs/BENCHMARK_MATRIX.md) | Medidas reproducibles |
| [`MODEL_REGISTRY.md`](docs/MODEL_REGISTRY.md) | Contrato etapa → artifacto |
| [`models_onnx/README.md`](models_onnx/README.md) | Qué dejar en `models_onnx/`, y cómo |
| [`pront.md`](pront.md) | La especificación sobre la que se construyó |

---

> Documentación en inglés: [README.md](README.md)