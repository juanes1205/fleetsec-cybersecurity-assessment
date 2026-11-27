# V-08 - Exposición de información personal en registros

## 1. Identificación

- **Código:** V-08
- **Vulnerabilidad:** Logging de información personal (PII)
- **CWE:** CWE-359 - Exposure of Private Personal Information to an Unauthorized Actor
- **OWASP:** A09 - Security Logging and Monitoring Failures (OWASP Top 10 2021)
- **CVSS de referencia:** 7.5 - High
- **Ley aplicable:** Ley 1581 de 2012 (Colombia), en relación con la protección de datos personales.

## 2. Descripción

El registro directo de objetos recibidos por una API puede provocar que información personal y credenciales queden almacenadas en los registros de aplicación.

En este laboratorio se demuestra cómo un endpoint registra información sensible sin sanitización y cómo un logger centralizado reduce esta exposición mediante redacción de campos sensibles y patrones conocidos.

## 3. Entorno de pruebas

- Node.js
- Express
- Jest
- Supertest
- Datos completamente ficticios.
- Ejecución local, sin servicios externos.

## 4. Prueba de concepto

Se implementaron dos endpoints aislados:

- `POST /vulnerable-log`: registra directamente el cuerpo de la solicitud.
- `POST /secure-log`: utiliza el logger centralizado con sanitización.

Los datos de prueba incluyen nombre, correo electrónico, teléfono, documento ficticio, contraseña y token ficticio.

El escenario vulnerable permite observar estos valores en los argumentos enviados a `console.log`.

El escenario seguro sustituye los valores de campos sensibles por `[REDACTED]` y redacta correos incrustados en mensajes de texto.

## 5. Impacto

Una exposición de datos personales en registros puede afectar la confidencialidad de la información y aumentar el riesgo de acceso indebido si los logs son consultados, descargados o centralizados sin controles adecuados.

En el contexto colombiano, esta situación debe evaluarse frente a las obligaciones aplicables de protección de datos personales de la Ley 1581 de 2012.

No se utilizaron datos personales reales en las pruebas.

## 6. Remediación

Se implementó un mecanismo centralizado de logging compuesto por:

- `src/utils/log-sanitizer.js`: sanitización recursiva de objetos, arreglos, errores y texto.
- `src/utils/secure-logger.js`: registro estructurado en JSON con niveles `info`, `warn` y `error`.

También se centralizó el logging de los componentes de inicialización, base de datos, servidor y manejo de errores.

Se evitó registrar el objeto de usuarios creado por el seeder, que anteriormente podía exponer direcciones de correo electrónico.

Morgan conserva el formato `:method :status :response-time ms`, sin registrar cuerpos, encabezados ni parámetros de consulta.

## 7. Validaciones realizadas

Las pruebas automatizadas verifican:

1. Exposición de datos ficticios en el escenario vulnerable.
2. Redacción de datos sensibles en el escenario seguro.
3. Protección en los niveles `info`, `warn` y `error`.
4. Conservación del flujo legítimo de la API.
5. Conservación de campos operativos no sensibles.

Además, se validó el comportamiento del sanitizador ante referencias compartidas y referencias circulares.

## 8. Limitaciones

La detección de información sensible dentro de objetos se basa principalmente en los nombres de sus propiedades. La sanitización de texto libre reconoce patrones específicos, como correos electrónicos, JWT y credenciales Bearer.

No se garantiza la detección de todos los formatos posibles de documentos, teléfonos o datos personales dentro de texto arbitrario.

La demostración es un laboratorio controlado y no constituye una auditoría de logs de producción ni una certificación de cumplimiento legal.

## 9. Resultado

**Estado: mitigación demostrada en laboratorio.**

- Pruebas V-08: 4 aprobadas.
- Suite completa: 77 pruebas aprobadas.
- Suites completas: 10 aprobadas.

Los resultados ejecutables se encuentran en:

- `test-results.txt`
- `full-suite-results.txt`
