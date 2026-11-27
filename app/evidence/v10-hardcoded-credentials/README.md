# V-10 - Hardcoded Credentials (CWE-798)

## Objetivo

Demostrar el riesgo de almacenar credenciales directamente en el código
fuente y verificar su mitigación mediante configuración externa.

## Alcance y contexto

Este escenario utiliza un laboratorio local con credenciales completamente
ficticias. No se utilizan credenciales reales, servicios externos ni
infraestructura de producción.

La revisión de la configuración de FleetSec identificó que:

- `src/config/auth.js` obtiene `JWT_SECRET` desde `process.env`.
- `src/config/seed.js` obtiene las contraseñas iniciales desde variables
  de entorno.
- `.env.example` declara las variables necesarias sin incluir valores
  de credenciales.
- Los archivos `.env` están excluidos del seguimiento mediante `.gitignore`.

Por tanto, no se afirma que exista una credencial de producción
incrustada en el código revisado.

## Demostración vulnerable

La función `getHardcodedCredential()` devuelve una contraseña ficticia
almacenada directamente en el código fuente.

Esto representa el riesgo de CWE-798: una persona con acceso al código
podría recuperar la credencial y utilizarla indebidamente si fuera real
y estuviera activa.

## Mitigación

La función `getEnvironmentCredential()`:

- Obtiene el valor desde una configuración externa.
- No contiene una contraseña predeterminada.
- No utiliza valores de respaldo.
- Rechaza variables ausentes o vacías.
- Rechaza configuraciones inválidas.

En un despliegue real, las credenciales deben suministrarse mediante
variables de entorno protegidas o un gestor de secretos, con permisos
mínimos, rotación y controles de acceso.

## Validaciones

La suite automatizada verifica:

1. La exposición de la credencial ficticia en la implementación vulnerable.
2. La lectura desde configuración externa en la implementación segura.
3. El rechazo de variables ausentes.
4. El rechazo de variables vacías.
5. El rechazo de configuraciones inválidas.

## Limitaciones

- Prueba local y controlada.
- No se realiza explotación contra servicios reales.
- No se valida una integración con AWS Secrets Manager.
- No se afirma que exista una exposición real de credenciales en producción.

## Referencias

- CWE-798: Use of Hard-coded Credentials.
  https://cwe.mitre.org/data/definitions/798.html
