# Laboratorio 05 — Informes que un auditor pueda interpretar

Las herramientas de seguridad deben explicar **qué han comprobado** y
**qué no pueden asegurar**. Este cambio incorpora dos objetos al JSON:

- `summary`: total y recuento de observaciones por severidad.
- `methodology`: tipo de análisis, número de peticiones y limitaciones.

## Ejecutar

Fusiona el PR y actualiza tu repositorio como usuario habitual:

~~~bash
cd ~/websec-auditor
source .venv/bin/activate
git pull --ff-only origin main
python -m pytest -q
~~~

Si el servidor HTTPS del laboratorio 4 sigue funcionando, puedes reutilizarlo
sin reiniciarlo: solo ha cambiado el cliente y el formato de sus informes.

~~~bash
websec-auditor https://127.0.0.1:8766/misconfigured \
  --lab-https --ca-file .lab-certs/ca.crt --output misconfigured-https.json
python -m json.tool misconfigured-https.json
~~~

La sección esperada de resumen será:

~~~json
{
  "summary": {
    "total_findings": 3,
    "by_severity": {
      "critical": 0,
      "high": 0,
      "medium": 2,
      "low": 1,
      "info": 0
    }
  }
}
~~~

El objeto `methodology` indicará `local_https_lab`, una petición,
y advertencias sobre los límites de la inspección.

## Interpretación

El servidor devuelve tres configuraciones débiles (CSP, HSTS y
Referrer-Policy). Las observaciones se agrupan por severidad para facilitar
su triaje. **No representan tres vulnerabilidades demostradas.**

Si ves 0 hallazgos en otro objetivo, nunca afirmes que es seguro:
el escáner analiza **una única respuesta**, no ejecuta aplicaciones web,
no hace crawling ni cubre toda la superficie de ataque.

## Ejercicio

1. Compara la severidad y el total con el array `findings`.
2. Comprueba que el informe `/hardened` muestra 0 y sigue indicando límites.
3. Inspecciona `src/websec_auditor/reporting.py`: localiza dónde se
   conservan las severidades desconocidas y cómo se selecciona `mode`.

Siguiente objetivo: añadir contexto técnico relevante a cada observación
sin filtrar valores de cookies ni generar falsos positivos.
