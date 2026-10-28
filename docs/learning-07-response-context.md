# Laboratorio 07 — Menos falsos positivos por tipo de respuesta

## Problema

Antes, se informaba de la ausencia de CSP y Referrer-Policy incluso al pedir
una respuesta JSON o un redireccionamiento. Eso confunde recomendaciones
propias de documentos HTML con respuestas que no contienen una página.

## Qué cambia

Se clasifican las respuestas por código de estado y Content-Type.

- Solo las respuestas **2xx con Content-Type text/html o application/xhtml+xml**
  activan los controles de CSP y Referrer-Policy en esta fase.
- JSON, imágenes, redirecciones, respuestas sin contenido, respuestas fallidas
  y tipos de contenido desconocidos omiten esas dos reglas.
- HSTS para HTTPS, X-Content-Type-Options y los atributos de cookies
  siguen examinándose cuando correspondan.

Es una heurística conservadora. Algunas otras respuestas pueden hacer uso de
políticas CSP o Referrer-Policy de distintas maneras: una regla omitida
**no implica seguridad**. En otras fases podremos añadir más contexto.

## Práctica con HTTPS real

1. Fusiona el PR y, como user1, actualiza tu repositorio:

~~~bash
cd ~/websec-auditor
source .venv/bin/activate
git pull --ff-only origin main
python -m pytest -q
~~~

2. **Reinicia** el servidor HTTPS anterior (Ctrl+C en su terminal) para que
   incorpore las nuevas rutas:

~~~bash
websec-auditor --lab-https-server \
  --cert-file .lab-certs/server.crt \
  --key-file .lab-certs/server.key
~~~

3. En otra terminal, ejecuta estas pruebas:

~~~bash
websec-auditor https://127.0.0.1:8766/json \
  --lab-https --ca-file .lab-certs/ca.crt --output json-https.json

websec-auditor https://127.0.0.1:8766/redirect \
  --lab-https --ca-file .lab-certs/ca.crt --output redirect-https.json

python -m json.tool json-https.json
python -m json.tool redirect-https.json
~~~

Ambas respuestas incorporan HSTS válido en TLS y nosniff, y no generan
hallazgos con las comprobaciones actuales. Sin embargo, reportan
`response_context.document_checks_applied: false` y
`methodology.skipped_checks: [content-security-policy, referrer-policy]`.

Para contrastar:

~~~bash
curl -i --cacert .lab-certs/ca.crt https://127.0.0.1:8766/json
curl -i --cacert .lab-certs/ca.crt https://127.0.0.1:8766/redirect
~~~

No uses curl -L: **el auditor no sigue redirecciones**, intencionadamente.

4. Vuelve a analizar la ruta HTML /misconfigured:

~~~bash
websec-auditor https://127.0.0.1:8766/misconfigured \
  --lab-https --ca-file .lab-certs/ca.crt \
  --output misconfigured-https.json

python -m json.tool misconfigured-https.json
~~~

Los tres hallazgos previos deberían permanecer.

## Interpretación

- Un hallazgo identifica una observación sobre una respuesta concreta, no
  una explotación demostrada.
- Una regla omitida no es un resultado negativo: es algo que **no se ha
  comprobado** para esa respuesta.
- El escáner envía una única petición y nunca sigue automáticamente un 302.
- No guardamos cuerpos ni valores de cookies en el JSON.
