# Laboratorio 06 — Evidencia técnica sin exponer secretos

Un informe profesional debe justificar cada hallazgo con hechos verificables.
Añadimos a cada objeto `finding` un campo opcional `evidence`.

Este campo guarda solo información **estructurada y seleccionada**:
- La cabecera observada y si falta.
- La directiva CSP eficaz en la que encontramos 'unsafe-eval'.
- La política Referrer-Policy seleccionada por el detector.
- El número HSTS `max_age_seconds` cuando vale cero.
- El nombre de cookie y el atributo ausente; **nunca su valor**.

**No guardamos el contenido completo de cabeceras ni el valor de ninguna cookie.**

## Práctica

Fusiona el PR y actualiza el proyecto como usuario normal:

~~~bash
cd ~/websec-auditor
source .venv/bin/activate
git pull --ff-only origin main
python -m pytest -q
~~~

El laboratorio HTTPS anterior puede permanecer abierto; no cambiamos el servidor.

~~~bash
websec-auditor https://127.0.0.1:8766/misconfigured \
  --lab-https \
  --ca-file .lab-certs/ca.crt \
  --output misconfigured-https.json

python -m json.tool misconfigured-https.json
~~~

Para `content-security-policy-unsafe-eval` verás una evidencia como:

~~~json
{
  "source": "response_header",
  "name": "content-security-policy",
  "effective_directive": "script-src",
  "matched_token": "'unsafe-eval'"
}
~~~

También verás `effective_policy: unsafe-url` para Referrer-Policy y
`max_age_seconds: 0` para HSTS.

**El total sigue siendo 3 hallazgos**; no hemos ampliado las reglas de
detección, sino mejorado la trazabilidad de cada resultado.

## Ejercicio

1. Comprueba que el valor de la cookie `session` no aparece en el JSON.
2. Relaciona cada evidencia con su cabecera en `curl -i --cacert .lab-certs/ca.crt https://127.0.0.1:8766/misconfigured`.
3. Revisa `tests/test_evidence.py` y observa qué valores evitamos copiar.

## Límites

La evidencia es una **justificación de la regla concreta**, no una
demostración de explotación o impacto real. La detección CSP solo cubre
un subconjunto de la semántica del navegador. Las cabeceras pueden
contener datos confidenciales en producción y no deben volcarse sin
criterio a los informes.
