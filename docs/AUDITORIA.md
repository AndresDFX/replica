# Auditoría AppSec + UX/A11Y — Replica (2026-11-25)

**Alcance:** panel web PWA servido por la Lambda `admin` (`src/lambda/entrypoints/admin.py`), API de
administración, flujos de vinculación (Telegram userbot, WhatsApp/Baileys) y gestión de secretos.
**Referencias:** OWASP ASVS 4.0 L2, WCAG 2.2 AA, Ley 1581/2012 (Habeas Data, Colombia).
**Fuera de alcance:** apps nativas (no existen; "móvil" = PWA instalada), pentest dinámico contra
producción, `whatsapp-service` (solo revisión indirecta vía el proxy).

**Suposiciones declaradas** (el contexto se dejó a criterio del auditor):

- Front de API Gateway HTTP API sin WAF.
- Varios usuarios en el panel, con rol `admin` o `user`.
- Se asume el escenario más crítico: un usuario `user` comprometido o malicioso, y un destinatario
  que controla su nombre de contacto (texto entrante no confiable).

Leyenda de estado: ✅ corregido en este commit · 🟡 mitigado parcialmente · ⏳ pendiente (plan por olas).

---

## Fase 2 — Hallazgos

### A. Seguridad

| ID | Hallazgo | Plataforma / Severidad | Estado |
|---|---|---|---|
| SEC-01 | Bloqueo anti-fuerza-bruta **global** → DoS del admin | Web — **Alta** | ✅ |
| SEC-02 | Sin cabeceras de seguridad (clickjacking, sniffing, caché de PII) | Web — **Alta** | ✅ / 🟡 CSP |
| SEC-03 | Rol `user` podía cambiar credenciales y **exfiltrar `whatsapp_token`** | Web/API — **Crítica** | ✅ |
| SEC-04 | `telethon_api_hash` devuelto en claro por `/api/config` | API — Media | ✅ |
| SEC-05 | Contraseña en `sessionStorage` (Basic Auth reenviado en cada petición) | Web — **Alta** | ⏳ Ola 2 |
| SEC-06 | CSP requiere `'unsafe-inline'` (JS y handlers inline) | Web — Media | ⏳ Ola 3 |
| SEC-07 | `bcEsc` no escapaba `'` ni `` ` ``; `data-id` sin escapar | Web — Media | ✅ |
| SEC-08 | Freno de intentos en memoria por contenedor (eludible con concurrencia) | API — Media | ⏳ Ola 2 |
| SEC-09 | Sin MFA para el panel, que gobierna dos cuentas personales | Web — Alta | ⏳ Ola 3 |
| SEC-10 | Política de contraseña mínima (8 caracteres, sin lista de filtradas) | Web — Baja | ⏳ Ola 2 |
| SEC-11 | Envío masivo a contactos sin registro de consentimiento/opt-out | Legal — Alta | ⏳ Ola 3 |

**SEC-01: bloqueo global.**
- **Diagnóstico:** `_AUTH` era un único contador para todo el panel. Cinco Basic Auth erróneos con
  *cualquier* usuario bloqueaban a **todos**, incluido el admin legítimo, durante 5 min.
- **Vector:** un script anónimo repite 5 intentos cada 5 min y deja el panel inutilizable de forma
  permanente, justo cuando hay que pausar un envío masivo.

**SEC-02: sin cabeceras de seguridad.**
- **Diagnóstico:** ninguna respuesta llevaba `CSP`, `X-Frame-Options`, `nosniff`, `HSTS` ni
  `Referrer-Policy`. Las respuestas JSON con PII (contactos y teléfonos) no llevaban `no-store`.
- **Vector:** clickjacking del panel, por ejemplo con botones "Enviar ahora" o "Eliminar todos"
  dentro de un iframe. Además, los datos podían quedar en caché del disco o de un proxy.

**SEC-03: escalada de un usuario normal.**
- **Diagnóstico:** el rol solo restringía la gestión de usuarios. Un `user` podía:
  - hacer `POST /api/config` con `whatsapp_service_url=https://atacante`; desde ahí el backend
    enviaba el `whatsapp_token` a ese servidor en cada proxy (exfiltración del secreto y SSRF);
  - reemplazar `bot_token` o `telethon_session`;
  - re-vincular WhatsApp o Telegram a una cuenta propia, o resetearlos.
- **Impacto:** toma de control de los canales de difusión y suplantación ante todos los contactos.

**SEC-04: `api_hash` en claro.**
- **Diagnóstico:** `/api/config` enmascaraba `bot_token`, la sesión y `whatsapp_token`, pero no el
  `api_hash`. Junto con `api_id`, es credencial de aplicación de Telegram.

**SEC-05: credencial reutilizable en el cliente.**
- **Diagnóstico:** el panel guarda `base64(usuario:contraseña)` en `sessionStorage` y lo manda
  como `Authorization: Basic` en cada petición.
- **Vector:** cualquier XSS, extensión maliciosa o equipo compartido obtiene la **contraseña**, no
  un token revocable. El logout no invalida nada en el servidor.

**SEC-06: CSP con `'unsafe-inline'`.**
- **Diagnóstico:** el shell tiene unos 160 KB de JS inline y `onclick=` por todas partes, así que
  la CSP aplicada todavía permite scripts inline. La defensa ante XSS sigue dependiendo del
  escape manual (`bcEsc`).

**SEC-07: escape incompleto.**
- **Diagnóstico:**
  - `bcEsc` no escapaba comillas simples ni backticks, y hay plantillas con atributos `'...'`
    dentro de `onclick`;
  - `data-id="${s.chatId}"` iba sin escapar;
  - los nombres de contactos de Telegram o WhatsApp los controla un tercero.
- **Estado:** hoy no se encontró una ruta explotable, pero el margen era nulo. Corregido como
  defensa en profundidad.

**SEC-08: freno de intentos solo en memoria.**
- **Diagnóstico:** el estado vive en memoria del contenedor. Varios contenedores en paralelo
  multiplican los intentos permitidos.
- **Mitigación actual:** el throttling de API Gateway.

**SEC-09: sin MFA.**
- **Diagnóstico:** el panel controla la cuenta personal de Telegram y la de WhatsApp. Basta con
  la contraseña para obtener ese control.

**SEC-10: política de contraseña débil.**
- **Diagnóstico:** solo se exige longitud ≥ 8. No hay comprobación contra contraseñas filtradas
  (k-anonimato con HIBP) ni medidor de fuerza en tiempo real.

**SEC-11: Habeas Data.**
- **Diagnóstico:** se difunde a contactos personales y listas sin evidencia de autorización
  previa ni un canal de baja. La Ley 1581 exige autorización, finalidad y mecanismo de supresión.

### B. UX, prevención de errores y accesibilidad

| ID | Hallazgo | Severidad | Estado |
|---|---|---|---|
| UX-01 | Un `user` ve Ajustes → Conexiones/credenciales que ya no puede guardar (recibe un 403 con mensaje) | Media | ⏳ Ola 2 |
| UX-02 | Quedan 2 `confirm()` nativos (fuera del design system, sin foco gestionado ni microcopy de consecuencia) | Media | ⏳ Ola 2 |
| UX-03 | Contraseñas nuevas sin `autocomplete="new-password"`, por lo que el gestor no ofrece generar ni guardar | Baja | ✅ |
| A11Y-01 | Campos de secretos sin `autocomplete="off"`, así que el navegador los guardaba en su historial | Baja | ✅ |
| A11Y-02 | `minlength` ausente: la política no se anuncia ni se valida antes del envío | Baja | ✅ (nativo) / ⏳ medidor en vivo |
| A11Y-03 | Contraste del modo "glass" (`backdrop-filter`) sin verificar con herramienta sobre fondos variables | Media | ⏳ Ola 3 |

Puntos ya correctos, verificados en el código:

- `lang` en `<html>` y foco visible (`:focus-visible`).
- Regiones `aria-live` para avisos y respeto de `prefers-reduced-motion`.
- Objetivos táctiles de ≥ 44 px en botones principales y no se bloquea el zoom.
- El *forgot* responde de forma genérica, sin enumeración de usuarios.
- El 429 da un mensaje con tiempo de espera.
- Los botones "ojo" cubren los 11 campos secretos.

---

## Fase 3 — Remediación

### Ola 1 — Hotfixes (aplicados en este commit)

1. **SEC-01:** el contador pasa a ser **por usuario normalizado** (`_auth_estado`,
   `_auth_desbloquear`), con un tope de 2000 entradas. El atacante solo se bloquea a sí mismo.
2. **SEC-02:** `lambda_handler` envuelve el dispatch y añade estas cabeceras a toda respuesta:
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
     img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self'; manifest-src 'self';
     worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'
   X-Frame-Options: DENY
   X-Content-Type-Options: nosniff
   Referrer-Policy: no-referrer
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
   Cross-Origin-Opener-Policy: same-origin
   Cache-Control: no-store            (solo respuestas application/json)
   ```
3. **SEC-03:** `_CAMPOS_SOLO_ADMIN`:
   - campos protegidos: `bot_token`, `telethon_api_id`, `telethon_api_hash`, `telethon_session`,
     `whatsapp_service_url`, `whatsapp_token`, `resend_api_key` y `send_mode`;
   - un `user` que intente cambiarlos recibe un **403** que nombra los campos;
   - además son solo para admin: `/api/whatsapp/pair`, `/api/whatsapp/reset`,
     `/api/telethon/send-code|sign-in|logout` y `POST /api/telegram/webhook`;
   - lo operativo (canal fuente, markup, listas, envíos) sigue abierto al rol `user`.
4. **SEC-04:** `telethon_api_hash` se enmascara y se expone `telethon_api_hash_set`. El input pasa
   a `type="password"` con su ojo, así que los campos secretos pasan de 10 a 11.
5. **SEC-07:** `bcEsc` escapa `& < > " ' \``; `data-id` escapado.
6. **UX-03 y A11Y-01/02:** atributos `autocomplete` y `minlength` correctos en los 11 campos.

**Pruebas añadidas** (`RoleTests.test_sec0*`):
- un bloqueo ajeno no tumba al admin;
- cabeceras presentes y `no-store`;
- 403 para un `user` en 4 campos y 5 rutas, mientras lo operativo sigue permitido;
- `api_hash` enmascarado.

Resultado de la suite: **441 passed**.

### Ola 2 — Sprint 1

**SEC-05: sesión con cookie.** Reemplazar Basic Auth por una sesión:

1. `POST /api/auth/login` verifica PBKDF2 y crea `sid = secrets.token_urlsafe(32)`. En DynamoDB se
   guarda solo `sha256(sid)` con `user`, `exp`, `ua` y TTL.
2. La respuesta lleva:
   `Set-Cookie: __Host-replica_sid=<sid>; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800`.
3. CSRF: con `SameSite=Strict`, más una cabecera `X-Requested-With: replica` obligatoria en las
   mutaciones y la comprobación de `Origin` contra el host.
4. `POST /api/auth/logout` borra la fila y expira la cookie. Al cambiar la contraseña se revocan
   todas las sesiones del usuario.
5. Front: `hdr()` deja de usar `CRED` y `fetch(..., {credentials:'same-origin'})`, y se elimina
   `sessionStorage.cred`.

Transición: aceptar Basic durante un release, con un aviso en el log.

**SEC-08: freno persistente.** Contador en DynamoDB `auth_fail#<user>` con `UpdateItem ADD` y TTL
de 15 min (atómico entre contenedores). Además, un throttle de API Gateway en `/api/*` de 10 rps
con ráfaga de 20.

**SEC-10:** mínimo 12 caracteres, comprobación HIBP de k-anonimato (5 primeros caracteres del SHA-1)
y un medidor accesible (`aria-describedby` con `aria-live="polite"`).

**UX-01:**
- `loadMe()` ya devuelve `is_admin`. Con `!IS_ADMIN`, el bloque de conexiones se renderiza en
  solo lectura con este aviso: *«Solo un administrador puede cambiar las conexiones y credenciales.
  Pídeselo a {admin}.»*
- Estados del bloque:
  - Idle (lectura): se ven los indicadores de conectado/desconectado.
  - Sin botones de acción.
- El 403 queda como red de seguridad.

**UX-02:** migrar los dos `confirm()` al modal del design system (`role="dialog"`, `aria-modal`,
foco atrapado y devuelto, Esc cancela). El CTA destructivo usa un verbo concreto
(*«Eliminar 37 contactos»*), y el foco inicial va en **Cancelar**.

### Ola 3 — Sprint 2

**SEC-06:** sacar el JS del shell a `/admin/app.js`, servido como asset igual que `sw.js`, y
cambiar los `onclick=` por `addEventListener` y delegación con `data-action`. Después:
`script-src 'self'`, sin `unsafe-inline`. Paso intermedio: `Content-Security-Policy-Report-Only`
con la política estricta para medir.

**SEC-09:** TOTP opcional y obligatorio para `admin`, con RFC 6238 en stdlib (`hmac` y `struct`):
- alta con QR y 10 códigos de recuperación hasheados;
- verificación en el login con ventana de ±1 paso;
- reutiliza el freno por usuario de SEC-01.

**SEC-11: Habeas Data.**
- Campo `consentimiento` (fecha y fuente) por contacto o lista.
- Footer de baja: *«Responde BAJA para no recibir más»*.
- `hub_entrada` marca la exclusión automáticamente.
- Una auditoría exportable.

**A11Y-03:** medir el contraste con axe-core y Playwright sobre las pantallas de
`scripts/capturas_ui.py`, en claro y oscuro. Objetivo: ≥ 4.5:1 para texto y ≥ 3:1 para controles.
Si falla, poner fondo sólido de respaldo con `@supports not (backdrop-filter)` y subir la opacidad
de `--glass`.

---

## Matriz de validación (QA)

| ID | Prueba | Tipo | Esperado |
|---|---|---|---|
| SEC-01 | 6 Basic Auth erróneos con `atacante` y luego login como admin | Unit (✅) / manual | atacante 429, admin 200 |
| SEC-02 | `curl -sI https://<host>/dev/admin` y `.../api/me` | Manual / smoke | Todas las cabeceras; JSON con `no-store` |
| SEC-02 | `<iframe src=panel>` en un HTML local | Manual | El navegador lo bloquea (frame-ancestors) |
| SEC-03 | Usuario `user`: POST config con `whatsapp_service_url` | Unit (✅) | 403, URL sin cambios |
| SEC-03 | Usuario `user`: cambiar canal fuente | Unit (✅) | 200 |
| SEC-04 | GET `/api/config` con hash guardado | Unit (✅) | `""` + `_set: true` |
| SEC-04 | Guardar config sin tocar el hash | Unit (existente) | No se vacía (`_NO_VACIAR`) |
| SEC-07 | Contacto llamado `x' onmouseover='alert(1)` en las listas | Manual / E2E | Se muestra literal, sin ejecutar |
| SEC-05 | `sessionStorage` tras el login | E2E (Ola 2) | Sin `cred`; cookie HttpOnly |
| SEC-08 | 20 intentos en paralelo | Carga (Ola 2) | Bloqueo a los 5, sin depender del contenedor |
| UX-01 | Iniciar sesión como `user` y abrir Ajustes | E2E (Ola 2) | Conexiones en solo lectura con aviso |
| A11Y | axe-core sobre las 5 pestañas, en claro y oscuro | E2E (Ola 3) | 0 violaciones serias o críticas |

**Riesgo de regresión de la Ola 1:** un usuario `user` que antes re-vinculaba WhatsApp o Telegram
ya no puede hacerlo. Es intencional: ahora lo hace un admin.
