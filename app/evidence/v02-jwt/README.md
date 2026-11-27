# V-02 - JWT / Autenticación rota

## Vulnerabilidad

CWE-345: Verificación insuficiente de la autenticidad de los datos.

## Objetivo

Demostrar los riesgos de aceptar las declaraciones (claims) de un
JSON Web Token (JWT) sin verificar la autenticidad e integridad del token.

## Comportamiento vulnerable

La función de laboratorio `unsafeDecodeToken()` utiliza `jwt.decode()`,
que extrae el contenido del token sin validar su firma.

Esto permite leer las declaraciones del token sin comprobar que hayan
sido emitidas por una fuente confiable ni que su contenido sea íntegro.

## Corrección de seguridad

El middleware de autenticación de la aplicación utiliza `jwt.verify()`
con las siguientes validaciones:

- Algoritmo HS256 explícito.
- Secreto JWT configurado mediante variable de entorno.
- Validación del emisor (`issuer`).
- Validación de la audiencia (`audience`).
- Validación de la expiración del token.
- Validación de las declaraciones obligatorias.

## Validación

Se ejecutaron correctamente ocho pruebas automatizadas con Jest.

Consulta el archivo `test-results.txt` para revisar los resultados
de la ejecución.

## Restricciones de seguridad

- La implementación vulnerable del laboratorio no se importa en
  la aplicación de producción.
- No debe exponerse mediante ningún endpoint de la API.
- Su uso está limitado a pruebas locales y controladas.
