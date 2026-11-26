# V-01 — SQL Injection

**Identificador:** V-01  
**CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command  
**Componente:** Laboratorio de búsqueda de activos  
**Estado:** Vulnerabilidad demostrada y corrección verificada.

## Descripción

Se implementó una consulta SQL deliberadamente vulnerable que incorpora directamente una entrada de usuario mediante concatenación de cadenas.

Esta condición permite alterar la lógica de la consulta SQL mediante entradas especialmente construidas.

## Evidencia de explotación

Se utilizó una base de datos SQLite en memoria con dos activos ficticios.

La entrada de prueba `' OR 1=1 -- ` modificó la condición SQL y permitió recuperar ambos registros, aunque la búsqueda original no correspondía a ninguno de ellos.

## Impacto

Una implementación equivalente en un componente real podría permitir manipular consultas y acceder a registros no previstos, dependiendo de los permisos de la conexión y de la estructura de la base de datos.

## Corrección aplicada

Se sustituyó la concatenación de cadenas por consultas parametrizadas mediante `db.prepare()` y parámetros enlazados.

## Validación

Se ejecutaron dos pruebas automatizadas:

- La consulta vulnerable devuelve dos registros ante la entrada manipulada.
- La consulta parametrizada devuelve cero registros ante la misma entrada.

**Resultado:** 2 pruebas aprobadas. La corrección fue verificada.

## Limitaciones

La explotación se realizó exclusivamente en un laboratorio local, utilizando SQLite en memoria y datos ficticios. No se expusieron endpoints vulnerables en la API de FleetSec.
