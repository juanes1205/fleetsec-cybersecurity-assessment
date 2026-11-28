# Mapeo MITRE ATT&CK v14 — Incidente FleetSec S.A.S.

**Incidente:** Compromiso de Cuenta Cloud, Escalación de Privilegios y Exfiltración Masiva  
**Matriz:** Enterprise Matrix / Cloud (AWS)  
**Versión de Framework:** MITRE ATT&CK® v14.1  

---

## Matriz Consolidada de Técnicas y Mitigaciones

| Táctica | ID Técnica | Nombre de Técnica | Manifestación en el Incidente FleetSec | Controles de Mitigación Técnicos |
|---|---|---|---|---|
| **Acceso Inicial** | `T1078.004` | Valid Accounts: Cloud Accounts | El adversario utilizó credenciales de larga duración comprometidas del usuario `svc-monitoring` desde la IP de salida Tor `185.220.101.22` para autenticarse en la consola de AWS a T+00:00. | 1. Implementación de roles IAM temporales (STS) en lugar de Access Keys estáticas.<br>2. MFA mandatorio y bloqueo de inicio de sesión de consola para cuentas de servicio.<br>3. WAF / SCP bloqueando llamadas de consola desde nodos Tor y países no autorizados. |
| **Persistencia** | `T1098` | Account Manipulation | A T+00:15, el atacante ejecutó `iam:CreateLoginProfile` sobre el usuario `svc-monitoring`, transformando una cuenta de servicio puramente programática en una cuenta interactiva con interfaz web. | 1. SCP (Service Control Policy) que deniega `iam:CreateLoginProfile` en todas las cuentas del Organization salvo excepciones del equipo de IAM.<br>2. Regla de AWS Config `iam-user-unused-credentials-check` y alerta CloudWatch en tiempo real ante creación de perfiles. |
| **Escalación de Privilegios** | `T1098.001` | Additional Cloud Credentials / Policy Attachment | A T+00:22, el atacante ejecutó `iam:AttachUserPolicy` adjudicándose la política `AdministratorAccess`, completando el control total del entorno cloud de FleetSec. | 1. IAM Permissions Boundaries aplicados de forma mandatoria que limitan el privilegio máximo alcanzable.<br>2. SCP que prohíbe asociar `AdministratorAccess` a cualquier entidad no autorizada.<br>3. Regla Sigma `rule1_cloudtrail_admin_escalation_offhours.yml`. |
| **Colección** | `T1530` | Data from Cloud Storage | A T+00:35, el atacante ejecutó 387 llamadas `s3:GetObject` en 8 minutos contra el bucket `fleetpay-prod-drivers`, extrayendo 45.7 GB de información personal sensible de conductores. | 1. Políticas de bucket S3 con restricción estricta de VPC Endpoint (`aws:sourceVpce`).<br>2. GuardDuty S3 Protection (`S3_DATA_EVENTS`).<br>3. Regla Sigma de detección de anomalías masivas `rule4_bonus_s3_bulk_getobject_anomaly.yml`. |
| **Evasión de Defensas** | `T1562.008` | Impair Defenses: Disable Cloud Logs | A T+01:45, el adversario intentó ejecutar `cloudtrail:DeleteTrail` para borrar el historial de auditoría y evitar la detección y atribución del ataque. Fue bloqueado con éxito por una SCP preventiva. | 1. Service Control Policy (SCP) en la raíz de AWS Organizations que deniega `cloudtrail:DeleteTrail` y `cloudtrail:StopLogging` a todos los usuarios, incluido Root.<br>2. Regla Sigma CRITICAL `rule2_cloudtrail_deletetrail_antiforensics.yml`. |
| **Persistencia / Ejecución** | `T1053.007` | Container Orchestration Job | A T+01:40, el atacante ejecutó `ecs:RegisterTaskDefinition` en el clúster de producción con la imagen maliciosa `docker.io/attacker/exfil:latest` para establecer un backdoor persistente en contenedores. | 1. Registro obligatorio en Amazon ECR privado con escaneo de vulnerabilidades y firma criptográfica de imágenes con AWS Signer.<br>2. Restricción en IAM/SCP para impedir el despliegue de imágenes provenientes de registros públicos no autorizados. |
| **Exfiltración** | `T1048.003` | Exfiltration Over Alternative Protocol | A T+01:10, la instancia `10.0.2.45` mantuvo una conexión saliente TCP/443 de 38 minutos hacia el nodo Tor `185.220.101.22`, transfiriendo ~49 GB de datos. | 1. Network Firewall / egress proxy con inspección TLS y bloqueo de tráfico hacia IPs de baja reputación o nodos Tor.<br>2. Monitoreo continuo mediante VPC Flow Logs con métricas de tráfico anómalo en CloudWatch. |
| **Mando y Control (C2)** | `T1071.004` | Application Layer Protocol: DNS | A T+01:50, la instancia `i-0abc1234def56789` ejecutó exfiltración encubierta fragmentando y codificando registros mediante peticiones DNS anómalas (`Trojan:EC2/DNSDataExfiltration`). | 1. Route 53 Resolver DNS Firewall con listas de dominios maliciosos habilitadas.<br>2. Amazon GuardDuty con alertas de severidad ALTA integradas a EventBridge y SNS para contención automática. |

---

## Cobertura Táctica (Kill Chain del Incidente)

```
[Initial Access]        T1078.004 (Valid Cloud Accounts)
       │
[Persistence]           T1098 (Account Manipulation)
       │
[Privilege Escalation]  T1098.001 (Additional Cloud Credentials)
       │
[Collection]            T1530 (Data from Cloud Storage)
       │
[Exfiltration]          T1048.003 (Exfiltration over Alternative Protocol)
       │
[Execution/Persistence] T1053.007 (Container Orchestration Job)
       │
[Defense Evasion]       T1562.008 (Disable Cloud Logs - Blocked by SCP)
       │
[Command & Control]     T1071.004 (DNS Tunneling / Data Exfiltration)
```
