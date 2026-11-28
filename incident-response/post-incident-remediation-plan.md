# Plan de Remediación Post-Incidente — FleetSec S.A.S.

**Incidente:** Compromiso de Infraestructura Cloud y Fuga de Información de Flota  
**Alcance:** Entorno AWS Producción, Red Corporativa y Gobierno de Datos Ley 1581 / ISO 27001  
**Aprobado por:** Ingeniero de Ciberseguridad & Dirección de Operaciones  

---

## Matriz Priorizada de Remediación

| ID | Prioridad | Acción de Remediación | Esfuerzo Estimado | Área Responsable | Criterio de Éxito / Entregable |
|---|:---:|---|:---:|---|---|
| **REM-01** | **P1 (0–7 d)** | **Rotación global de credenciales y llaves IAM/KMS:** Invalidación forzosa de todas las Access Keys activas en la organización, rotación de secrets en Secrets Manager y generación de nuevas CMK para datos en reposo. | 16 horas | Cloud Ops / Infosec | Cero credenciales estáticas con antigüedad mayor a 7 días. |
| **REM-02** | **P1 (0–7 d)** | **Imposición de MFA obligatorio y eliminación de consolas en cuentas de servicio:** Aplicar SCP en AWS Organizations que bloquee cualquier llamada de consola sin MFA y prohibir perfiles interactivos en identidades de servicio. | 8 horas | Infosec | SCP activa en la raíz; 100% de usuarios humanos con MFA por hardware/FIDO2 o TOTP. |
| **REM-03** | **P1 (0–7 d)** | **Aislamiento de red y bloqueo de nodos Tor / proxies anónimos:** Configurar en WAF y NACLs el bloqueo estricto de direcciones IP clasificadas como Tor Exit Nodes y ASNs sospechosos, restringiendo accesos a Colombia, Perú y USA. | 12 horas | DevSecOps / Redes | WAF bloqueando el 100% de peticiones originadas fuera de los países y ASNs autorizados. |
| **REM-04** | **P1 (0–7 d)** | **Preparación y radicación de notificación formal ante la SIC:** Redacción del informe técnico-jurídico y presentación del reporte de brecha ante el Registro Nacional de Bases de Datos (RNBD) de la SIC (plazo máx. 15 días hábiles). | 24 horas | Legal & Compliance / Infosec | Radicado oficial de notificación generado ante la SIC dentro de los primeros 5 días hábiles. |
| **REM-05** | **P2 (8–30 d)** | **Implementación de IAM Permissions Boundaries:** Aplicar barreras de permisos automáticas a todos los roles y usuarios que impidan la auto-asignación de privilegios administrativos o modificaciones a la auditoría. | 32 horas | Cloud Ops / Infosec | Ningún rol/usuario puede auto-elevarse a `AdministratorAccess` aun teniendo permisos de IAM. |
| **REM-06** | **P2 (8–30 d)** | **Restricción de S3 mediante VPC Endpoints y DLP:** Modificar políticas de buckets sensibles (`fleetpay-*`) para que solo acepten conexiones autenticadas originadas desde el VPC Endpoint privado (`aws:sourceVpce`). | 20 horas | DevSecOps | Acceso a S3 desde Internet completamente bloqueado; descargas masivas limitadas a ráfagas de 50 req/min. |
| **REM-07** | **P2 (8–30 d)** | **Hardening y escaneo de imágenes de contenedores en ECR:** Bloquear el despliegue de contenedores de repositorios públicos en ECS; forzar imágenes firmadas con AWS Signer y escaneadas con Trivy. | 40 horas | DevSecOps | Pipeline CI/CD bloqueando cualquier imagen sin tag SHA pinneado o con vulnerabilidades críticas. |
| **REM-08** | **P2 (8–30 d)** | **Estrategia de comunicación y notificación a conductores afectados:** Implementar canal seguro de atención y soporte para los ~60,000 conductores afectados bajo lineamientos de la Ley 1581. | 48 horas | Legal / Comunicaciones / RRHH | Comunicado oficial emitido con recomendaciones de protección crediticia y monitoreo de fraudes. |
| **REM-09** | **P3 (31–90 d)** | **Automatización de respuesta SOAR y Centro de Operaciones 24/7:** Configurar EventBridge + Lambdas de respuesta automatizada para aislar instancias EC2 y revocar IAM en <60 segundos ante alertas HIGH de GuardDuty. | 80 horas | Infosec / SecOps | Tiempo promedio de contención (MTTC) reducido de 2 horas a <3 minutos. |
| **REM-10** | **P3 (31–90 d)** | **Certificación ISO 27001:2022 y auditoría externa independiente:** Remediar brechas del SGSI en el tratamiento de telemetría y contratar firma externa acreditada para pentesting y auditoría de certificación. | 160 horas | Infosec / Gerencia de Calidad | Auditoría externa con 0 no conformidades mayores y certificación ISO 27001 aprobada. |

---

## Cronograma y Asignación de Recursos

```
Semanas:     [S1]       [S2]       [S3]       [S4]       [M2-M3]
P1 (0-7d):   ████████
P2 (8-30d):             ██████████████████████
P3 (31-90d):                                             ████████████████████████
```

* **Carga total estimada:** ~440 horas hombre.
* **Gobernanza:** Reuniones semanales del Comité de Seguridad presidido por el CEO y reporte mensual de avance hacia la Junta Directiva.
