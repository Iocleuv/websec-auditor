# Laboratorio 02 — Servidor HTTP real en tu VM

Este laboratorio **sí levanta un servidor HTTP real** dentro de tu máquina virtual y el auditor le hace peticiones HTTP reales a través de 127.0.0.1. Solo se escucha en la interfaz de loopback: no queda expuesto a la red.

## 0. Preparación

Usa tu usuario habitual, no root:

~~~bash
cd ~/websec-auditor
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
~~~

## 1. Arranca el servidor (terminal A)

~~~bash
websec-auditor --lab-server
~~~

El servidor estará en http://127.0.0.1:8765/. Déjalo abierto mientras realizas el análisis.

## 2. Analiza sus respuestas reales (terminal B)

~~~bash
cd ~/websec-auditor
source .venv/bin/activate
websec-auditor http://127.0.0.1:8765/insecure --lab --output insecure-real.json
websec-auditor http://127.0.0.1:8765/hardened --lab --output hardened-real.json
~~~

Para visualizar los hallazgos:

~~~bash
python -m json.tool insecure-real.json
python -m json.tool hardened-real.json
~~~

También puedes inspeccionar directamente las respuestas HTTP:

~~~bash
curl -i http://127.0.0.1:8765/insecure
curl -i http://127.0.0.1:8765/hardened
~~~

Debes observar **cinco hallazgos** para /insecure y **cero** para /hardened, según las cinco comprobaciones aplicables a HTTP. Los valores de las cookies son ficticios.

## 3. ¿Por qué ya no aparecen los siete hallazgos de la demo HTTPS?

- Este laboratorio utiliza **HTTP sin cifrar**, por simplicidad y porque solo es accesible dentro de la VM.
- Strict-Transport-Security (HSTS) se comprueba solo en HTTPS.
- El detector del atributo de cookie Secure se evalúa únicamente en respuestas HTTPS, como en el código original.
- Hardened significa que cumple las comprobaciones aplicables a este ejemplo, **no que HTTP sea seguro para autenticación real**. No se utilizan secretos reales.

## 4. Cerrar

En la terminal A, pulsa Ctrl+C.

## Límites importantes

- El modo --lab admite exclusivamente http://127.0.0.1:8765/insecure y http://127.0.0.1:8765/hardened.
- No abras el puerto 8765 en otras interfaces.
- Este CLI no implementa defensas suficientes contra SSRF para desplegarlo como servicio web multiusuario.
- No confundas una cabecera ausente con una vulnerabilidad explotable demostrada.
- En la siguiente fase configuraremos HTTPS con un certificado local de prueba.
