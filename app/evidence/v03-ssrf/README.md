# V-03 – Server-Side Request Forgery (SSRF)

## 1. Información general

| Campo               | Descripción                                                       |
| ------------------- | ----------------------------------------------------------------- |
| Identificador       | V-03                                                              |
| Vulnerabilidad      | Server-Side Request Forgery (SSRF)                                |
| CWE                 | CWE-918                                                           |
| Componente evaluado | Función de recuperación de recursos HTTP/HTTPS                    |
| Resultado           | Vulnerabilidad demostrada y controles de mitigación implementados |

### Descripción

Server-Side Request Forgery (SSRF) es una vulnerabilidad que permite a un atacante inducir a una aplicación del lado del servidor a realizar solicitudes HTTP hacia destinos no previstos.

Un atacante podría intentar utilizar esta condición para acceder a servicios internos, interfaces administrativas, direcciones de loopback o servicios de metadatos de infraestructura cloud.

La vulnerabilidad se relaciona con CWE-918: _Server-Side Request Forgery (SSRF)_.

## 2. Comportamiento vulnerable

La función `vulnerableFetch()` implementa una recuperación de recursos HTTP/HTTPS sin validar adecuadamente el destino solicitado.

La implementación vulnerable:

- Acepta destinos proporcionados directamente.
- No restringe los dominios permitidos.
- No verifica si la dirección IP de destino es privada, pública o reservada.
- No impide solicitudes hacia servicios locales.

### Demostración

Se implementó un servidor HTTP ficticio en `127.0.0.1`, disponible exclusivamente durante las pruebas automatizadas.

La prueba demuestra que `vulnerableFetch()` puede acceder al servidor local y recuperar su respuesta HTTP.

No se utilizaron servicios internos reales ni infraestructura externa.

## 3. Controles implementados

La función `secureFetch()` incorpora controles de validación antes de realizar solicitudes.

### 3.1. Validación de URL y protocolo

- Solo permite HTTPS.
- Rechaza URLs inválidas.
- Rechaza credenciales incluidas en la URL.
- Restringe los puertos al 443.
- Rechaza direcciones IP literales.
- Utiliza una lista de dominios autorizados.

### 3.2. Validación de direcciones IP

La función `isPublicIp()` utiliza `ipaddr.js` para identificar direcciones que no deben considerarse destinos públicos.

Se rechazan, entre otras:

- Direcciones IPv4 privadas.
- Direcciones IPv4 de loopback.
- Direcciones IPv4 link-local.
- Direcciones IPv4 CGNAT.
- Direcciones IPv4 multicast y no especificadas.
- Direcciones IPv6 loopback.
- Direcciones IPv6 privadas y link-local.
- Direcciones IPv4 mapeadas en IPv6 cuando representan direcciones privadas.
- Direcciones IPv6 reservadas para documentación.

### 3.3. Validación DNS

`resolveAndValidateHost()` resuelve el dominio y verifica todas las direcciones IP obtenidas.

Si alguna dirección no es pública, se rechaza el destino completo.

La función `secureFetch()` utiliza las direcciones previamente validadas en la conexión, evitando una nueva resolución DNS independiente durante la solicitud.

### 3.4. Controles adicionales

- Rechazo de redirecciones HTTP para evitar cambios de destino no validados.
- Tiempo máximo de solicitud.
- Límite máximo de respuesta de 1 MB.
- Validación del certificado TLS mediante `rejectUnauthorized`.
- Uso de SNI para el dominio autorizado.

## 4. Pruebas de seguridad

Las pruebas automatizadas se encuentran en:

`tests/vapt/v03-ssrf.test.js`

Se ejecutaron 22 pruebas que verifican:

| Validación                                   | Resultado |
| -------------------------------------------- | --------- |
| Identificación de IPv4 pública               | Aprobada  |
| Rechazo de IPv4 privada                      | Aprobada  |
| Rechazo de loopback IPv4                     | Aprobada  |
| Rechazo de link-local IPv4                   | Aprobada  |
| Rechazo de loopback IPv6                     | Aprobada  |
| Rechazo de IPv6 privada                      | Aprobada  |
| Rechazo de IPv6 link-local                   | Aprobada  |
| Rechazo de DNS con IP no pública             | Aprobada  |
| Bloqueo de conexión ante DNS privado         | Aprobada  |
| Rechazo de redirecciones HTTP                | Aprobada  |
| Demostración de acceso local vulnerable      | Aprobada  |
| Rechazo de protocolo HTTP                    | Aprobada  |
| Rechazo de localhost                         | Aprobada  |
| Rechazo de dominios no autorizados           | Aprobada  |
| Rechazo de credenciales en URL               | Aprobada  |
| Rechazo de puertos diferentes a 443          | Aprobada  |
| Rechazo de CGNAT                             | Aprobada  |
| Rechazo de multicast                         | Aprobada  |
| Rechazo de dirección no especificada         | Aprobada  |
| Rechazo de IPv4 privada mapeada en IPv6      | Aprobada  |
| Rechazo de IPv6 reservada para documentación | Aprobada  |

### Resultado de las pruebas específicas

- Suites ejecutadas: 1
- Suites aprobadas: 1
- Pruebas ejecutadas: 22
- Pruebas aprobadas: 22
- Pruebas fallidas: 0

Evidencia: `test-results.txt`.

### Resultado de la suite completa

- Suites ejecutadas: 4
- Suites aprobadas: 4
- Pruebas ejecutadas: 39
- Pruebas aprobadas: 39
- Pruebas fallidas: 0

Evidencia: `full-suite-results.txt`.

## 5. Alcance y limitaciones del laboratorio

Este escenario se ejecutó en un entorno local y controlado.

- Se utilizó un servidor HTTP ficticio en loopback para demostrar el comportamiento vulnerable.
- No se realizaron solicitudes contra servicios internos reales.
- No se accedió a metadatos de proveedores cloud.
- El dominio `api.example.com` representa el dominio autorizado de laboratorio y no implica que se haya probado un servicio externo real.
- Las solicitudes de la implementación segura se validaron mediante pruebas automatizadas y simulaciones controladas.
- La clasificación de direcciones IP depende de las categorías reconocidas por `ipaddr.js`; una clasificación como unicast no garantiza por sí sola que una dirección sea globalmente enrutable.
- La lista de dominios autorizados debe configurarse según los destinos legítimos del entorno de producción.

Para una implementación productiva también se recomienda aplicar controles de salida de red (_egress filtering_), políticas de firewall y monitoreo de solicitudes salientes.

## 6. Archivos relacionados

- `src/vapt/v03-ssrf/ssrf.lab.js`: implementación vulnerable y versión con controles de mitigación.
- `tests/vapt/v03-ssrf.test.js`: pruebas automatizadas.
- `evidence/v03-ssrf/test-results.txt`: evidencia de las pruebas específicas.
- `evidence/v03-ssrf/full-suite-results.txt`: evidencia de la suite completa.

## 7. Conclusión

Se demostró el comportamiento de una vulnerabilidad SSRF mediante una implementación deliberadamente vulnerable y un servidor local ficticio.

Posteriormente, se implementaron controles de validación de URL, restricción de dominios, validación DNS e IP, prevención de redirecciones y límites de solicitud.

Las 22 pruebas específicas de V-03 y las 39 pruebas de la suite completa finalizaron satisfactoriamente.

El laboratorio demuestra la aplicación de controles defensivos frente a SSRF en un entorno local controlado.
