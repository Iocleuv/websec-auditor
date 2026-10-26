# Laboratorio 01 — Cabeceras HTTP y cookies

Este laboratorio usa **únicamente metadatos sintéticos**. No envía peticiones a Internet.

## 1. Ejecutar dos perfiles

```bash
websec-auditor --demo --profile insecure --output insecure.json
websec-auditor --demo --profile hardened --output hardened.json
```

- `insecure` simula una respuesta sin varias cabeceras y con una cookie sin atributos de protección; actualmente genera siete observaciones.
- `hardened` simula una respuesta configurada para satisfacer las comprobaciones implementadas; actualmente genera cero observaciones.

> Que el escáner no encuentre observaciones **no demuestra que el sitio sea seguro**: no se evalúan la autenticación, autorización, lógica de negocio, control de accesos ni vulnerabilidades de aplicación.

## 2. Entender los hallazgos

| Campo | Para qué sirve | Precaución |
| --- | --- | --- |
| `Content-Security-Policy` | Restringir qué contenido puede cargar la página | La mera presencia de CSP no garantiza una política robusta |
| `X-Content-Type-Options: nosniff` | Evitar determinados comportamientos de detección de MIME | No corrige controles de acceso deficientes |
| `Referrer-Policy` | Controlar cuánta información de URL se envía como Referer | Depende de la privacidad que requiera la aplicación |
| `Strict-Transport-Security` | Preferir HTTPS en accesos posteriores | Su configuración exige valorar subdominios y despliegue |
| Cookie `Secure` | Restringir el envío de la cookie a conexiones seguras | No sustituye una gestión de sesiones correcta |
| Cookie `HttpOnly` | Impedir acceso directo mediante JavaScript | Puede ser inapropiado para cookies que JS deba leer |
| Cookie `SameSite` | Reducir el envío de cookies en ciertos contextos entre sitios | No sustituye todas las medidas anti-CSRF |

## 3. Ejercicio práctico

1. Compara el array `findings` de los dos informes.
2. Explica por qué faltan cuatro cabeceras y tres atributos en el perfil `insecure`.
3. Investiga por qué **no** sería correcto afirmar que `hardened` está libre de vulnerabilidades.
4. Ejecuta `pytest -q` y revisa `tests/test_demo_profiles.py`.

## 4. Siguiente práctica

Crear un servicio HTTP de laboratorio en una VM aislada, añadir o quitar cabeceras deliberadamente y comprobar cómo cambian los resultados de manera autorizada.
