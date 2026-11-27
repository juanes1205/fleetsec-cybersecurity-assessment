# V-07 - Missing Rate Limiting

## Identificación

- ID: V-07
- Vulnerabilidad: Missing Rate Limiting
- CWE: CWE-307 - Improper Restriction of Excessive Authentication Attempts
- OWASP Top 10 2021: A07 - Identification and Authentication Failures
- CVSS de referencia: 7.5 (High)
- Endpoint afectado: POST /api/auth/login

## Descripción

El endpoint de autenticación sin limitación de solicitudes permite
realizar múltiples intentos de inicio de sesión sin restricciones
temporales, facilitando ataques de fuerza bruta y credential stuffing.

## Prueba de concepto

Se implementó un laboratorio local con dos versiones del endpoint:

1. Versión vulnerable: acepta múltiples intentos fallidos sin aplicar
   limitación.
2. Versión segura: restringe los intentos por dirección IP y devuelve
   HTTP 429 cuando se supera el límite.

El laboratorio utiliza exclusivamente credenciales ficticias y no
interactúa con servicios externos.

## Evidencia de la remediación

Se incorporó express-rate-limit al endpoint real:

POST /api/auth/login

Configuración predeterminada:

- Ventana: 15 minutos.
- Máximo: 5 solicitudes por IP.
- Respuesta al superar el límite: HTTP 429.
- Encabezados estándar RateLimit.
- Mensaje genérico para evitar revelar información innecesaria.

Los valores pueden configurarse mediante:

- LOGIN_RATE_LIMIT_WINDOW_MS
- LOGIN_RATE_LIMIT_MAX

## Pruebas realizadas

### Laboratorio

- Múltiples intentos fallidos permitidos en la versión vulnerable.
- Autenticación legítima permitida.
- Solicitudes dentro del límite permitidas en la versión segura.
- Solicitudes por encima del límite bloqueadas con HTTP 429.
- Encabezados informativos verificados.

### Integración con la API real

Se utilizó una base de datos independiente:

data/fleetsec.v07.test.db

Resultado:

- Login legítimo: HTTP 200.
- Cuatro intentos fallidos: HTTP 401.
- Sexta solicitud total: HTTP 429.
- Encabezado RateLimit presente.

### Suite completa

- Suites aprobadas: 9.
- Pruebas aprobadas: 73.
- Pruebas fallidas: 0.

## Impacto

La ausencia de limitación de intentos puede facilitar ataques
automatizados contra cuentas de usuario. Si un atacante consigue
adivinar o reutilizar credenciales, podría obtener acceso no autorizado
a información de vehículos, usuarios y documentos.

Esto puede comprometer la confidencialidad e integridad de los datos
personales tratados por FleetSec, con implicaciones para la Ley 1581
de 2012.

## Consideraciones de despliegue

La configuración implementada utiliza el almacenamiento en memoria
predeterminado de express-rate-limit.

En un despliegue con múltiples instancias, contenedores o procesos,
se debe configurar un almacenamiento compartido, por ejemplo Redis,
para mantener un contador consistente entre instancias.

También se recomienda complementar el control por IP con monitoreo
de intentos por cuenta, alertas de comportamiento anómalo y políticas
de bloqueo progresivo cuidadosamente diseñadas.

## Estado

Remediación implementada y validada mediante pruebas automatizadas.
