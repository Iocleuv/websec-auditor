# Laboratorio 04 — Cabeceras presentes, pero mal configuradas

Hasta ahora, WebSec Auditor identificaba principalmente cabeceras ausentes. El
nuevo perfil /misconfigured devuelve **cabeceras presentes**, pero valores que
debilitan algunas protecciones.

## Preparación

1. Revisa y fusiona el PR que introduce el perfil /misconfigured.
2. Trabaja como usuario habitual, sin root.
3. Actualiza el proyecto:

~~~bash
cd ~/websec-auditor
source .venv/bin/activate
git pull --ff-only origin main
python -m pip install -e ".[dev]"
python -m pytest -q
~~~

No regeneres los certificados si .lab-certs ya existe y no han caducado.

## Arrancar el servidor HTTPS (terminal A)

Detén antes con Ctrl+C cualquier servidor de la versión antigua y vuelve a
iniciarlo para cargar los cambios:

~~~bash
websec-auditor --lab-https-server --cert-file .lab-certs/server.crt --key-file .lab-certs/server.key
~~~

## Analizar el tercer perfil (terminal B)

~~~bash
cd ~/websec-auditor
source .venv/bin/activate

websec-auditor https://127.0.0.1:8766/misconfigured --lab-https \
  --ca-file .lab-certs/ca.crt --output misconfigured-https.json

python -m json.tool misconfigured-https.json

curl -i --cacert .lab-certs/ca.crt https://127.0.0.1:8766/misconfigured
~~~

Resultados esperados para las comprobaciones actuales:

| Cabecera | Valor de prueba | Observación |
| --- | --- | --- |
| CSP | script-src con 'unsafe-eval' | content-security-policy-unsafe-eval |
| Referrer-Policy | unsafe-url | referrer-policy-unsafe-url |
| HSTS | max-age=0 | strict-transport-security-disabled |

La cookie sí tiene Secure, HttpOnly y SameSite para HTTPS, así que no genera
observaciones relativas a esos atributos. Se espera un total de **tres
hallazgos**. El certificado local sigue validándose mediante --ca-file.

## ¿Por qué importan estos valores?

- CSP 'unsafe-eval': permite determinados métodos de evaluación dinámica de
  cadenas como JavaScript y reduce esa protección de CSP.
- Referrer-Policy unsafe-url: puede revelar rutas y parámetros de URL en el
  encabezado Referer, incluso hacia destinos menos seguros.
- HSTS max-age=0: puede desactivar la política HSTS en navegadores para
  **nombres de host compatibles**. Aquí verificamos únicamente el valor de
  cabecera; un navegador no aplica HSTS a la dirección IP literal de
  127.0.0.1.

**Un hallazgo es una observación técnica a revisar, no la demostración de un
ataque explotable.** Estas comprobaciones son deliberadamente limitadas y no
sustituyen un parser completo de CSP/HSTS ni las pruebas de aplicación.

## Tu ejercicio

1. Comprueba que curl muestra las tres cabeceras.
2. Relaciona cada cabecera con el hallazgo del JSON.
3. Compara el resultado con /hardened (cero hallazgos en las pruebas actuales).
4. Revisa tests/test_header_values.py para entender las comprobaciones.

Referencias:
- MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src
- MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy
- MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security
