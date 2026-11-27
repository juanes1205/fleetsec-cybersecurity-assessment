# V-04 – XML External Entity (XXE)

**Identificador:** V-04
**CWE:** CWE-611 – Improper Restriction of XML External Entity Reference
**Estado:** Implementación y pruebas completadas.

## 1. Objetivo

Demostrar el riesgo asociado al procesamiento inseguro de documentos XML que contienen declaraciones de entidades externas y documentar una implementación que rechaza este tipo de declaraciones.

## 2. Escenario vulnerable controlado

Se implementó `vulnerableParseXml()` en:

`src/vapt/v04-xxe/xxe.lab.js`

Esta función simula la resolución insegura de entidades externas mediante recursos ficticios proporcionados en memoria (_fixtures_).

El escenario demuestra cómo una entidad externa podría sustituirse por contenido no previsto cuando una implementación permite su resolución sin controles adecuados.

**Importante:** esta demostración es una simulación controlada. No realiza solicitudes de red, no lee archivos del sistema operativo y no explota una vulnerabilidad real de `fast-xml-parser`.

## 3. Implementación segura

Se implementó `secureParseXml()` utilizando `fast-xml-parser`.

Controles aplicados:

- Rechazo de documentos que contienen declaraciones `DOCTYPE`.
- Rechazo de declaraciones `ENTITY`.
- Validación de la estructura XML antes del procesamiento.
- Límite máximo de tamaño de 64 KiB.
- Configuración `processEntities: false`.
- Rechazo de entradas que no sean cadenas.
- Conservación de referencias de entidades predefinidas cuando el procesamiento de entidades está desactivado.

## 4. Pruebas realizadas

Archivo:

`tests/vapt/v04-xxe.test.js`

Se implementaron 11 pruebas:

### Simulación vulnerable

1. Demuestra la expansión de una entidad externa ficticia.
2. Rechaza recursos ficticios inexistentes.
3. Acepta XML normal sin DTD.
4. Rechaza entradas que no son cadenas.

### Implementación segura

5. Bloquea documentos que contienen `DOCTYPE`.
6. Bloquea declaraciones `ENTITY`.
7. Analiza correctamente documentos XML normales.
8. Rechaza entradas que no son cadenas.
9. Rechaza documentos XML malformados.
10. Rechaza documentos que superan el tamaño máximo.
11. Conserva referencias de entidades predefinidas con `processEntities` desactivado.

## 5. Resultados

**Pruebas individuales V-04:**

`evidence/v04-xxe/test-results.txt`

Resultado: 11 pruebas aprobadas.

**Suite completa del proyecto:**

`evidence/v04-xxe/full-suite-results.txt`

Resultado:

- Test Suites: 5 passed, 5 total.
- Tests: 50 passed, 50 total.

## 6. Aislamiento y alcance

El laboratorio se encuentra separado de la API de producción.

- No se exponen endpoints vulnerables.
- No se utilizan archivos confidenciales reales.
- No se realizan conexiones externas para resolver entidades.
- Los datos de demostración son ficticios.

## 7. Limitaciones

La simulación vulnerable reproduce el comportamiento de expansión de una entidad externa mediante fixtures controlados. No representa una explotación real de una biblioteca XML vulnerable.

La implementación segura utiliza `fast-xml-parser` con validaciones previas y procesamiento de entidades desactivado. Los controles deben mantenerse y revisarse ante cambios de versión o configuración de la biblioteca.

## 8. Conclusión

Se completó la demostración controlada del riesgo XXE y se implementaron controles para rechazar DTD y declaraciones de entidades externas. Las 11 pruebas individuales y las 50 pruebas de la suite completa finalizaron satisfactoriamente.
