# V-05 - Mass Assignment (CWE-915)

## 1. Información general

- **Identificador:** V-05
- **Vulnerabilidad:** Mass Assignment
- **CWE:** CWE-915 - Improperly Controlled Modification of Dynamically-Determined Object Attributes
- **Severidad estimada:** Alta
- **Estado:** Mitigada en la implementación segura del laboratorio.
- **Entorno:** Laboratorio aislado con objetos ficticios en memoria.

## 2. Descripción

Mass Assignment ocurre cuando una aplicación asigna automáticamente propiedades recibidas desde una solicitud sin verificar si el usuario tiene autorización para modificarlas.

Un atacante podría enviar atributos adicionales que no deberían estar disponibles para actualización, como `role`, `activo` o `id`.

## 3. Escenario vulnerable

Archivo: `src/vapt/v05-mass-assignment/mass-assignment.lab.js`

La función `vulnerableUpdateUser` utiliza `Object.assign(user, input)` para copiar todas las propiedades recibidas.

Ejemplo de entrada:

```json
{
  "nombre": "Usuario de prueba",
  "role": "admin"
}
```

El resultado demuestra que un usuario con rol `user` puede modificar su propio rol a `admin`.

**Impacto potencial:**

- Escalamiento de privilegios.
- Modificación de atributos protegidos.
- Alteración de información que debería controlar exclusivamente el servidor.

## 4. Mitigación implementada

La función `secureUpdateUser` utiliza una lista explícita de atributos permitidos:

- `nombre`
- `email`

Los atributos no autorizados se ignoran. Además, se genera un nuevo objeto para evitar modificar directamente el objeto original.

Los campos `id`, `role` y `activo` permanecen protegidos.

## 5. Pruebas de seguridad

Archivo: `tests/vapt/v05-mass-assignment.test.js`

Se implementaron 9 pruebas para verificar:

1. Demostración de modificación no autorizada del rol.
2. Actualización de campos permitidos.
3. Protección de atributos sensibles.
4. Rechazo de propiedades no autorizadas.
5. Conservación del objeto original.
6. Rechazo de usuario inválido.
7. Rechazo de datos nulos.
8. Rechazo de arreglos como entrada.
9. Rechazo de arreglos como usuario.

## 6. Resultados

### Pruebas individuales

- Suites: 1 aprobada.
- Pruebas: 9 aprobadas.
- Fallos: 0.

### Suite completa

- Suites: 6 aprobadas.
- Pruebas: 59 aprobadas.
- Fallos: 0.

Los resultados detallados se encuentran en:

- `test-results.txt`
- `full-suite-results.txt`

## 7. Alcance y limitaciones

Este escenario es una simulación educativa y controlada que utiliza objetos ficticios en memoria.

No realiza modificaciones sobre usuarios reales, no ejecuta solicitudes contra la API de producción y no modifica la base de datos.

La implementación segura demuestra el uso de listas permitidas para controlar los atributos que pueden modificarse.
