# INFORME EJECUTIVO DE SEGURIDAD PARA DIRECCIÓN GENERAL (CEO)

**Para:** Dirección General y Junta Directiva — FleetSec S.A.S.  
**De:** Ingeniero de Ciberseguridad  
**Fecha:** 28 de Noviembre de 2026  
**Asunto:** Notificación de Incidente Crítico de Seguridad, Fuga de Información y Plan de Acción Inmediato  
**Clasificación:** ESTRICTAMENTE CONFIDENCIAL / PRIVILEGIADO  

---

### 1. ¿Qué ocurrió? (Resumen de los Hechos)
En las primeras horas de hoy (00:00 UTC), un actor malintencionado no autorizado logró vulnerar una cuenta de servicio de monitoreo en nuestra infraestructura cloud (AWS). Utilizando redes de anonimización (Tor), el atacante escaló privilegios hasta obtener control de administrador y procedió a extraer información de nuestros repositorios de almacenamiento seguro. 

El incidente se mantuvo activo durante dos horas antes de ser detectado y neutralizado. Gracias a una política de protección preventiva preconfigurada en nuestra cuenta, **se impidió que el atacante destruyera los registros de auditoría**, lo que nos ha permitido reconstruir con precisión matemática todo lo que fue sustraído.

---

### 2. ¿Qué datos fueron expuestos?
El atacante descargó un volumen total de **45.7 GB** perteneciente al sistema central de conductores (`fleetpay-prod-drivers`). El análisis forense confirma la exposición de registros de aproximadamente **60,000 vehículos y conductores asociados**, incluyendo:
* **Datos de identificación personal:** Nombres completos, números de cédula, licencias de conducción e información de contacto.
* **Datos financieros y de pagos:** Certificaciones bancarias, números de cuenta y montos liquidados para dispersión de pagos.
* **Telemetría y geolocalización:** Registros de rutas, ubicaciones de flota y horarios de operación de vehículos.

---

### 3. Impacto Legal y Regulatorio (Ley 1581 de 2012)
Bajo la legislación colombiana de protección de datos personales (**Ley 1581 de 2012**) y la Circular Externa 002 de la **Superintendencia de Industria y Comercio (SIC)**:
* **Obligación Legal de Notificación:** FleetSec tiene un plazo perentorio de **máximo 15 días hábiles** a partir de hoy para reportar formalmente este incidente ante la SIC a través del Registro Nacional de Bases de Datos (RNBD).
* **Riesgo Sancionatorio:** Ocultar o demorar la notificación acarrea multas sucesivas de hasta **2,000 salarios mínimos legales mensuales vigentes (SMMLV)** (aprox. \$2,600 millones COP) y posibles órdenes de suspensión temporal de operaciones de tratamiento de datos.
* **Impacto Comercial:** Existe riesgo de pérdida de confianza con clientes corporativos de flotas si la comunicación no se maneja con transparencia técnica y liderazgo proactivo.

---

### 4. Tres Acciones Inmediatas Recomendadas (Decisiones Requeridas)

1. **Aprobación de la Contención Total y Congelamiento Operativo (En Curso):**
   * Respaldar el bloqueo inmediato de todas las credenciales del usuario vulnerado, el aislamiento de la infraestructura afectada y la preservación forense de evidencias para la investigación oficial.
2. **Activación Inmediata del Comité de Crisis y Notificación a la SIC:**
   * Autorizar al equipo legal y de ciberseguridad a preparar el expediente técnico y radicar la notificación preventiva ante la Delegatura de Protección de Datos Personales de la SIC dentro de los próximos 3 días hábiles (muy por delante del plazo límite de 15 días).
3. **Imposición Mandatoria de Acceso Cero Confianza (Zero Trust):**
   * Ordenar la rotación del 100% de las contraseñas y llaves de acceso en la compañía, la exigencia estricta de Autenticación Multifactor (MFA) obligatoria para todo el personal y la contratación de un servicio de monitoreo y respuesta a incidentes 24/7.
