# V-09 - IDOR: acceso a documentos de otros usuarios

## 1. Identificación

- **Código:** V-09
- **Vulnerabilidad:** Insecure Direct Object Reference (IDOR)
- **CWE:** CWE-639 - Authorization Bypass Through User-Controlled Key
- **OWASP:** A01 - Broken Access Control (OWASP Top 10 2021)
- **CVSS de referencia:** 6.5 - Medium
- **Activo evaluado:** API de documentos de FleetSec.

## 2. Descripción

La vulnerabilidad IDOR ocurre cuando una aplicación utiliza un identificador proporcionado por el cliente para acceder a un recurso sin comprobar que el usuario autenticado tenga autorización sobre dicho recurso.

En el escenario vulnerable, un usuario autenticado puede consultar un documento perteneciente a otro usuario conociendo o manipulando su identificador.

La autenticación por sí sola no garantiza la autorización sobre cada objeto solicitado.

## 3. Entorno de pruebas

- Node.js
- Express
- SQLite mediante `node:sqlite`
- Jest
- Supertest
- JWT con algoritmo HS256.
- Usuarios, activos y documentos ficticios.
- Base de datos independiente: `fleetsec.v09.test.db`.
- Ejecución local, sin servicios externos ni datos reales.

## 4. Prueba de concepto

Se implementaron dos endpoints aislados en el laboratorio:

- `GET /api/idor/vulnerable/documents/:id`
- `GET /api/idor/secure/documents/:id`

Ambos requieren un JWT válido.

El endpoint vulnerable consulta el documento por su identificador, sin comprobar la propiedad del activo asociado.

El endpoint seguro agrega una condición de autorización a la consulta SQL: el activo asociado al documento debe pertenecer al usuario autenticado.

La prueba utiliza dos usuarios ficticios con rol `user` y un documento asociado exclusivamente al activo del propietario.

Un usuario diferente consigue consultar el documento mediante el endpoint vulnerable (`200`). El mismo usuario recibe `404` al intentar acceder mediante el endpoint seguro.

## 5. Impacto

- **Confidencialidad:** un usuario podría consultar documentos de otros usuarios si conoce o consigue sus identificadores.
- **Integridad:** si operaciones de modificación o eliminación no aplican controles equivalentes de propiedad, podrían permitir alteraciones o eliminación de recursos ajenos. Estas operaciones no forman parte de la PoC implementada.
- **Disponibilidad:** no se demostró impacto directo sobre la disponibilidad.

Si los documentos contienen información personal, una exposición no autorizada también debe evaluarse frente a las obligaciones aplicables de protección de datos personales de la Ley 1581 de 2012.

No se utilizaron documentos ni datos personales reales.

## 6. Remediación

Se incorporó protección en la API real:

- `src/controllers/document.controller.js`: consulta el documento mediante su identificador y el ID del propietario autenticado.
- `src/routes/document.routes.js`: aplica `authenticateToken` a `GET /:id`.
- `src/app.js`: monta las rutas bajo `/api/documents`.

La consulta SQL utiliza simultáneamente el identificador del documento y `assets.owner_user_id`, comparándolo con `req.user.id`.

Cuando el documento no existe o no pertenece al usuario, la API responde `404 Document not found`, evitando revelar la existencia de recursos ajenos.

La respuesta no expone el identificador interno del propietario.

## 7. Validaciones realizadas

Las pruebas automatizadas verifican:

1. Un usuario autenticado puede acceder al documento ajeno en el endpoint vulnerable.
2. El endpoint seguro del laboratorio deniega el acceso al usuario que no es propietario.
3. El propietario puede consultar su documento en el laboratorio.
4. Se rechazan solicitudes sin JWT.
5. Se rechazan identificadores inválidos.
6. El propietario puede consultar su documento mediante la API real.
7. La API real deniega el acceso de otro usuario.
8. La API real rechaza solicitudes sin autenticación.
9. La API real no revela documentos mediante identificadores inválidos.

## 8. Limitaciones

La demostración utiliza una base de datos SQLite local y datos ficticios.

La PoC demuestra acceso no autorizado de lectura. No se implementaron pruebas de modificación o eliminación de documentos.

La protección incorporada corresponde al endpoint de consulta de documentos. Cualquier nuevo endpoint que permita modificar, descargar o eliminar documentos deberá aplicar controles de autorización equivalentes.

No se realizó una evaluación de una infraestructura desplegada en producción.

## 9. Resultado

**Estado: mitigación de acceso no autorizado demostrada en laboratorio y en la API real.**

- Pruebas específicas de V-09: 9 aprobadas.
- Pruebas del laboratorio: 5 aprobadas.
- Pruebas de la API real: 4 aprobadas.
- Suite completa: 11 suites aprobadas y 86 pruebas aprobadas.

Los resultados ejecutables se encuentran en:

- `test-results.txt`: pruebas específicas de V-09.
- `full-suite-results.txt`: resultado de la suite completa.
