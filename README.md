# FleetSec S.A.S. — Cybersecurity Assessment & Defense Baseline

Repositorio de ingeniería de seguridad y remediación para la plataforma de telemetría de flotas (+60,000 vehículos) de **FleetSec S.A.S.**

---

## 03. Hardening de Infraestructura AWS — IaC Terraform

El módulo `modules/security-baseline` y la configuración raíz de Terraform en `/terraform` implementan la arquitectura de defensa en profundidad para FleetSec, alineada a los estándares **CIS AWS Foundations Benchmark v1.4**, **ISO 27001:2022** y la **Ley 1581 de 2012** (Protección de Datos Personales en Colombia).

### Arquitectura de Red y Segmentación (VPC 3 Capas)
* **Capa Pública (`public`):** Aloja el Application Load Balancer (ALB). Expone exclusivamente puertos 80 y 443 a Internet (`0.0.0.0/0`).
* **Capa de Aplicación (`app`):** Subredes privadas que albergan las tareas ECS/contenedores. Solo reciben tráfico del ALB en puerto `8080` y tienen salida estrictamente autorizada al puerto `5432` de la capa de datos.
* **Capa de Datos (`data`):** Subredes privadas aisladas con Network ACLs (NACLs) restrictivos y Security Groups que solo permiten tráfico TCP entrante en puerto `5432` desde la capa de aplicación y la Lambda de rotación de secretos. Sin acceso a Internet ni endpoints públicos.
* **VPC Flow Logs:** Registro dual habilitado con captura `ALL` hacia CloudWatch Logs (cifrado con KMS) y hacia el bucket S3 inmutable de auditoría.

---

### Matriz de Cumplimiento de Controles de Seguridad

| ID Control | Estándar CIS AWS v1.4 | Cláusula ISO 27001:2022 | Requisito Ley 1581 de 2012 | Control Técnico Implementado en Terraform | Estado |
|---|---|---|---|---|:---:|
| **SEC-01** | 1.4 — IAM Password Policy | A.9.4.3 Gestión de contraseñas | Art. 17 lit. d — Seguridad de la información | Política de contraseñas: mín. 14 caracteres, mayúsculas, minúsculas, símbolos, números, rotación a 90 días y memoria de 24 contraseñas previas. | **PASS** |
| **SEC-02** | 1.16 — Root account usage | A.9.2.3 Gestión de accesos privilegiados | Art. 17 lit. b — Acceso restringido | Sin claves de acceso para root; regla de AWS Config `root-account-mfa-enabled` y filtro de métricas CloudWatch para alerta inmediata de login root. | **PASS** |
| **SEC-03** | 2.1.1 — S3 Block Public Access | A.8.20 Seguridad en redes y servicios | Art. 17 lit. a — Confidencialidad y reserva | Recurso `aws_s3_account_public_access_block` aplicado a nivel de cuenta completa y buckets individuales con bloqueo total de ACLs y políticas públicas. | **PASS** |
| **SEC-04** | 2.1.2 — S3 SSE-KMS CMK | A.8.24 Uso de criptografía | Art. 17 lit. d — Principio de seguridad | Cifrado Server-Side mandatorio con Customer Managed Key (CMK) dedicada por servicio (`aws_kms_key.service["s3"]`), rotación anual y denegación de tráfico HTTP sin TLS (`SecureTransport = false`). | **PASS** |
| **SEC-05** | 2.1.5 — S3 Object Lock & Audit | A.8.10 Retención y destrucción de registros | Art. 17 lit. f — Conservación e integridad | Bucket de auditoría (`fleetsec-audit`) configurado con `Object Lock` en modo `COMPLIANCE` (retención inmutable de 365 días), versionado activo y transición a Glacier tras 180 días. | **PASS** |
| **SEC-06** | 2.2.1 — RDS Encryption in Transit & Rest | A.8.24 Criptografía de datos sensibles | Art. 17 lit. d — Integridad de datos | Instancia RDS PostgreSQL con cifrado en reposo CMK KMS (`gp3`), sin endpoint público, backups diarios (7 días de retención), Multi-AZ y parameter group forzando `rds.force_ssl = 1` y `log_connections = 1`. | **PASS** |
| **SEC-07** | 2.9 — Secrets Management & IAM Least Privilege | A.9.4.2 Procedimientos de inicio de sesión seguro | Art. 17 lit. b — Autorización y necesidad | Credenciales de base de datos administradas por AWS Secrets Manager con rotación automática a 30 días vía endpoint privado VPC. Las tareas ECS solo acceden mediante IAM Role de mínimo privilegio específico al ARN del secreto. | **PASS** |
| **SEC-08** | 3.1 & 3.2 — Multi-Region CloudTrail con CMK | A.8.15 Registro de eventos (Logging) | Art. 17 lit. e — Monitoreo de accesos | CloudTrail multi-región con `enable_log_file_validation = true`, cifrado con CMK KMS, entrega a S3 inmutable y streaming a CloudWatch Logs. | **PASS** |
| **SEC-09** | 3.3 a 3.14 — Alarmas CloudWatch para eventos críticos | A.8.16 Actividades de monitoreo | Art. 17 lit. d — Detección oportuna de brechas | Filtros de métricas y alarmas en tiempo real con envío a tópico SNS cifrado ante: uso de cuenta Root, cambios de políticas IAM, modificaciones a Security Groups e intentos de desactivar rotación de llaves KMS (`DisableKeyRotation`). | **PASS** |
| **SEC-10** | 3.15 — Amazon GuardDuty con protección avanzada | A.8.16 Detección de anomalías | Art. 17 lit. d — Alerta temprana de incidentes | GuardDuty activo con `S3_DATA_EVENTS` y `EBS_MALWARE_PROTECTION`. Regla EventBridge para enrutar automáticamente hallazgos de severidad ALTA/CRÍTICA (>= 7.0) a SNS para escalamiento IR. | **PASS** |
| **SEC-11** | AWS Foundational Security Best Practices (FSBP) | A.5.36 Conformidad con políticas de seguridad | Art. 17 lit. d — Cumplimiento normativo | Suscripción automática a estándares FSBP y CIS AWS Foundations v1.4 en AWS Security Hub para monitoreo de postura de seguridad continua (CSPM). | **PASS** |
| **SEC-12** | 4.1 & 4.2 — Segmentación de red y Security Groups | A.8.20 Control de tráfico de red | Art. 17 lit. a — Prevención de fuga de datos | Cero Security Groups con apertura `0.0.0.0/0` en puertos 22 o 3389. Solo el ALB expone 80/443; el tráfico Este-Oeste está estrictamente canalizado por SG referenciados unidireccionalmente. | **PASS** |

---

### Configuración del WAFv2 (Web Application Firewall)

El Web ACL Regional (`fleetsec-production-web-acl`) implementa cinco capas de protección perimetral:

1. **Geo-Restricción (`GeoMatchRestriction` - Priority 10 - BLOCK):**
   * Países autorizados: Colombia (`CO`), Perú (`PE`) y Estados Unidos (`US`).
   * Tráfico originado fuera de estas ubicaciones es bloqueado en el borde.
2. **Rate Limiting en Autenticación (`AuthRateLimit` - Priority 20 - BLOCK):**
   * Límite estricto de **1,000 solicitudes / 5 minutos** por dirección IP aplicado específicamente al path `/api/auth/*` para neutralizar ataques de fuerza bruta, credential stuffing y bypass de tokens.
3. **AWS Managed Rules - SQL Injection (`AWSManagedRulesSQLiRuleSet` - Priority 30 - BLOCK):**
   * Bloqueo inmediato de patrones maliciosos en query strings, headers y cuerpo HTTP.
4. **AWS Managed Rules - Known Bad Inputs (`AWSManagedRulesKnownBadInputsRuleSet` - Priority 40 - BLOCK):**
   * Bloqueo de exploits conocidos, inyecciones de comandos OS y traversals.
5. **AWS Managed Rules - Common Rule Set (`AWSManagedRulesCommonRuleSet` - Priority 50 - BLOCK con excepciones justificadas):**
   * Bloquea vectores generales de OWASP Top 10.
   * **Justificación técnica de COUNT vs BLOCK:**
     * `SizeRestrictions_BODY`: Se configura en modo **`COUNT`** porque la telemetría de flotas enviada en lotes JSON por dispositivos IoT (>60,000 vehículos) supera frecuentemente los 8 KB predeterminados de la regla. Mantenerla en BLOCK causaría falsos positivos masivos e interrupción del servicio de telemetría.
     * Todas las demás reglas (RFI, XSS, Restricted Extensions) se ejecutan en **`BLOCK`**.

#### Impacto del Geo-bloqueo en Usuarios con VPN y Estrategia de Excepciones
* **Impacto identificado:** Empleados o contratistas que usen soluciones VPN comerciales o nodos de salida corporativos en Europa u otras regiones no autorizadas recibirán respuestas HTTP 403 Forbidden.
* **Estrategia de Excepciones:**
  1. **IP Set de Allowlist Prioritario (Priority 5):** Un `aws_wafv2_ip_set` para los bloques CIDR de las VPN corporativas y oficinas remotas que permite el paso directo antes de evaluar la regla geográfica.
  2. **Encabezado de Tráfico Verificado (`X-FleetSec-Partner-Token` / mTLS):** Para integraciones B2B transfronterizas, autenticación mutua TLS (mTLS) a nivel de Load Balancer o validación de header criptográfico firmado.

---

### Instrucciones de Validación y Despliegue de Terraform

La infraestructura está modelada para permitir validación sintáctica y ejecución de plan sin necesidad de credenciales reales activas en AWS (soporta ejecución offline de mock providers):

```bash
# 1. Navegar al directorio de Terraform
cd terraform

# 2. Inicializar los proveedores y módulos
terraform init

# 3. Validar sintaxis y referencias
terraform validate

# 4. Ejecutar el plan de ejecución de seguridad (105 recursos planificados)
terraform plan
```

**Resultado de Validación:**
* `terraform validate`: `Success! The configuration is valid.` (0 errores, 0 warnings).
* `terraform plan`: `Plan: 105 to add, 0 to change, 0 to destroy.`
