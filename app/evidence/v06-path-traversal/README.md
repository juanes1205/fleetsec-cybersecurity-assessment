# V-06 - Path Traversal (CWE-22)

## 1. Información general

- Identificador: V-06
- Vulnerabilidad: Path Traversal
- CWE: CWE-22 - Improper Limitation of a Pathname to a Restricted Directory
- CVSS de referencia: 7.5
- Severidad de referencia: High
- OWASP Top 10 2021: A01 - Broken Access Control
- Estado: Remediación implementada y pruebas automatizadas exitosas.

## 2. Descripción

La vulnerabilidad Path Traversal ocurre cuando una aplicación utiliza
una ruta proporcionada por el usuario sin validar que el archivo solicitado
permanezca dentro del directorio autorizado.

Un atacante podría utilizar secuencias como ../ para acceder a archivos
ubicados fuera del directorio previsto.

## 3. Demostración controlada

Se implementó un laboratorio aislado con dos endpoints HTTP locales:

- GET /api/files-vulnerable
- GET /api/files-secure

La prueba utiliza archivos ficticios creados en un directorio temporal.

### Solicitud vulnerable

GET /api/files-vulnerable?file=../private/secret.txt

Resultado esperado: HTTP 200.

La aplicación vulnerable permite leer el archivo ficticio ubicado fuera
del directorio público.

### Solicitud corregida

GET /api/files-secure?file=../private/secret.txt

Resultado esperado: HTTP 403.

La aplicación corregida rechaza el acceso fuera del directorio autorizado.

## 4. Impacto

Una explotación en un sistema real podría permitir:

- Lectura no autorizada de archivos.
- Exposición de configuraciones y credenciales.
- Divulgación de información personal.
- Acceso a archivos internos de la aplicación.

En FleetSec, una exposición de información personal podría comprometer
la confidencialidad de los datos tratados y generar obligaciones relacionadas
con la Ley 1581 de 2012.

## 5. Remediación

Se implementó:

- Validación del tipo y contenido de la entrada.
- Rechazo de rutas absolutas.
- Resolución de rutas canónicas mediante realpathSync.
- Validación de que la ruta final permanezca dentro del directorio permitido.
- Protección frente a escapes mediante enlaces simbólicos.
- Respuestas controladas ante solicitudes inválidas o archivos inexistentes.

## 6. Evidencia de pruebas

Archivo de pruebas:

tests/vapt/v06-path-traversal.test.js

Resultado:

- Suites: 1 passed.
- Pruebas: 8 passed.
- Pruebas fallidas: 0.

Las pruebas verifican tanto la explotación controlada como la remediación
y el funcionamiento legítimo.

## 7. Alcance y limitaciones

Este escenario es un laboratorio automatizado local. No se realizaron
solicitudes contra sistemas externos ni se accedió a archivos reales
del sistema operativo.

Los endpoints del laboratorio no están integrados en la API principal
de FleetSec.
