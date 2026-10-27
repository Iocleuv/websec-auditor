# Laboratorio 03 — HTTPS real y verificación de certificados

**Objetivo:** ejecutar un servidor TLS en la propia máquina virtual, verificar su certificado mediante una CA local de prueba y comparar configuraciones HTTPS.

Los dos perfiles solo se sirven en 127.0.0.1 (loopback). No hay contraseñas ni sesiones reales.

## 0. Preparar (sin root)

~~~bash
cd ~/websec-auditor
source .venv/bin/activate
git pull origin main
python -m pip install -e '.[dev]'
pytest -q
openssl version
~~~

Se necesita el ejecutable openssl para crear certificados. No uses sudo pip y no arranques el laboratorio como root.

## 1. Generar certificados locales

~~~bash
python scripts/create_lab_certs.py
~~~

Esto crea .lab-certs/ con una CA de prueba y un certificado de servidor firmado por ella. El certificado de servidor tiene el identificador IP SAN 127.0.0.1. Los archivos privados quedan ignorados por Git.

- La CA solo se confía al pasar --ca-file, **no** se añade al almacén de confianza del sistema.
- La CA dura 30 días; el certificado de servidor dura 7 días.
- Si los archivos existen, el generador se niega a sobrescribirlos. Para regenerarlos, guarda o elimina conscientemente esa carpeta primero.
- No copies las claves a GitHub ni utilices esta CA para proteger servicios reales.

## 2. Terminal A: servidor HTTPS real

~~~bash
websec-auditor --lab-https-server --cert-file .lab-certs/server.crt --key-file .lab-certs/server.key
~~~

URL local: https://127.0.0.1:8766/. Mantén abierta esta terminal.

## 3. Terminal B: escanear por HTTPS

~~~bash
cd ~/websec-auditor
source .venv/bin/activate

websec-auditor https://127.0.0.1:8766/insecure --lab-https --ca-file .lab-certs/ca.crt --output insecure-https.json
websec-auditor https://127.0.0.1:8766/hardened --lab-https --ca-file .lab-certs/ca.crt --output hardened-https.json

python -m json.tool insecure-https.json
python -m json.tool hardened-https.json
~~~

Resultados esperados con los controles actuales:

- /insecure: siete observaciones (cuatro cabeceras + tres atributos de cookie).
- /hardened: cero observaciones.
- En ambos, el campo tls.certificate_verified: true indica que la conexión HTTPS fue aceptada por la verificación TLS **usando exclusivamente la CA local proporcionada**.

## 4. Ver cabeceras directamente

~~~bash
curl -i --cacert .lab-certs/ca.crt https://127.0.0.1:8766/insecure
curl -i --cacert .lab-certs/ca.crt https://127.0.0.1:8766/hardened
~~~

Sin --cacert, curl debería rechazar por defecto el certificado de laboratorio no reconocido. **No uses curl -k ni verify=False** como solución: no verificar el certificado ocultaría el fallo que estamos aprendiendo a detectar.

## 5. Qué valida y qué no valida

- TLS dificulta que terceros lean o modifiquen el tráfico en tránsito cuando la conexión está autenticada y configurada correctamente.
- La CA local permite verificar la cadena del certificado y la coincidencia del identificador IP SAN.
- El servidor rechaza conexiones con TLS inferior a 1.2 por configuración.
- El proyecto **todavía no enumera cifrados, versiones admitidas, OCSP ni caducidad detallada de certificados**. Eso vendrá después.
- HSTS exige contexto de navegador y nombres DNS: un navegador normalmente ignora HSTS anunciado por una dirección IP como 127.0.0.1. En este laboratorio solo inspeccionamos la cabecera.
- Una cookie con Secure no sustituye HttpOnly, SameSite, una gestión correcta de sesiones ni la seguridad de la aplicación.
- Cero hallazgos solo significa que no fallaron nuestras comprobaciones actuales, no que el sitio sea seguro.

## 6. Cerrar

Pulsa Ctrl+C en la terminal A para detener el servidor HTTPS. El servidor HTTP antiguo del puerto 8765 funciona por separado y no es necesario para esta práctica.
