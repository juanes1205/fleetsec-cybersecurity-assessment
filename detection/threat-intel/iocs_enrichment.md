# FleetSec S.A.S. — Threat Intelligence & IOC Enrichment Report

**Incidente:** Compromiso de Credenciales de Servicio y Exfiltración Masiva de Datos de Flota  
**Fecha de Detección:** T+02:00 UTC  
**Severidad Global:** CRÍTICA (Breach Activo con Exfiltración Confirmada de 45.7 GB / ~49 GB de Datos Personales)  
**Marco Legal:** Ley 1581 de 2012 (Colombia) / ISO 27001:2022

---

## 1. Tabla Consolidada de Indicadores de Compromiso (IOCs)

| Tipo               | Indicador / Valor                 | Contexto en la Línea de Tiempo                                                                                                 | Confianza | Clasificación TLP |
| ------------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | :-------: | :---------------: |
| **IPv4 Externa**   | `185.220.101.22`                  | IP de origen del login no autorizado a la consola (T+00:00) y destino del túnel de exfiltración de 49 GB (T+01:10).            |   Alta    |     TLP:CLEAR     |
| **IPv4 Interna**   | `10.0.2.45`                       | Host privado en subred `app` que originó la sesión saliente TCP/39201 hacia la IP del atacante.                                |   Alta    |     TLP:AMBER     |
| **Identidad IAM**  | `svc-monitoring`                  | Usuario de servicio programático comprometido. Se le habilitó consola interactiva y privilegios de `AdministratorAccess`.      |   Alta    |     TLP:AMBER     |
| **Instancia EC2**  | `i-0abc1234def56789`              | Instancia comprometida ejecutando malware de exfiltración de datos vía tunelización DNS (`Trojan:EC2/DNSDataExfiltration`).    |   Alta    |     TLP:AMBER     |
| **Imagen Docker**  | `docker.io/attacker/exfil:latest` | Contenedor registrado como Task Definition en ECS Producción para persistencia y backdoor.                                     |   Alta    |     TLP:CLEAR     |
| **Recurso S3**     | `fleetpay-prod-drivers`           | Bucket de producción conteniendo información sensible de conductores de flota y pagos. Víctima de 387 `s3:GetObject` en 8 min. |   Alta    |     TLP:AMBER     |
| **Llave KMS CMK**  | `prod-data-key`                   | Llave Customer Managed Key vulnerada para descifrar los payloads descargados (12 llamadas `kms:Decrypt`).                      |   Alta    |     TLP:AMBER     |
| **Llamada de API** | `cloudtrail:DeleteTrail`          | Intento explícito de borrar el rastro de auditoría a T+01:45 (bloqueado por Service Control Policy - SCP).                     |   Alta    |     TLP:AMBER     |

---

## 2. Enriquecimiento de Inteligencia de Amenazas (Threat Intelligence)

### IOC Externo Principal: `185.220.101.22`

| Fuente                      | Atributo Enriquecido              | Valor / Hallazgo                                                                                                                            |
| --------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Geolocalización**         | País / Ciudad / Coordenadas       | Alemania (`DE`) / Frankfurt am Main / `50.1109, 8.6821`                                                                                     |
| **Enrutamiento / ASN**      | Sistema Autónomo                  | **AS 213151** (Zwiebelfreunde e.V. / Calyx Institute / Tor Network Exit Nodes)                                                              |
| **Tipo de Infraestructura** | Categoría de Red                  | **Tor Exit Node Activo** (verificado en la lista oficial de consensos de Tor Project)                                                       |
| **AbuseIPDB**               | Reputación & Nivel de Confianza   | **100% Abuse Confidence Score** (Más de 1,200 reportes en las últimas 72 horas por scanning, brute-force y explotación web)                 |
| **VirusTotal**              | Detección de Motores de Seguridad | **14/92 motores marcan la IP como Maliciosa / Spam / Tor Proxy** (CrowdSec, AlienVault, Fortinet, CyRadar)                                  |
| **Shodan**                  | Servicios y Puertos Expuestos     | Puertos `443/tcp` (HTTPS / Tor ORPort), `9001/tcp` (Tor relay), Certificado autofirmado rotativo de Tor                                     |
| **MISP / AlienVault OTX**   | Feeds Comunitarios                | Asociado a pulsos: _Tor Exit Nodes Dynamic Feed_, _APT Anonymous Proxy Infrastructure_, _Active Brute-Force & Credential Stuffing Campaign_ |

### Análisis de la Imagen Maliciosa: `docker.io/attacker/exfil:latest`

- **Repositorio:** Docker Hub público (`registry-1.docker.io/attacker/exfil`).
- **Función táctica:** Herramienta de exfiltración continua y tunelización inversa C2 (Command & Control).
- **Riesgo:** El atacante buscaba establecer persistencia dentro del clúster de producción ECS mediante `ecs:RegisterTaskDefinition`, lo que habría permitido la reconexión automatizada en caso de rotación de credenciales.

---

## 3. Patrones de Comportamiento Anómalo (TTPs)

```
[00:00 UTC] Acceso Inicial vía Tor ---> [00:15 UTC] Creación de Consola Interactiva
                                                       |
[00:35 UTC] Exfiltración S3 (45.7 GB) <--- [00:22 UTC] Escalación AdministratorAccess
      |
[00:58 UTC] Descifrado KMS CMK (12x)
      |
[01:10 UTC] Exfiltración de Red VPC Flow Logs (49 GB saliente durante 38 min)
      |
[01:40 UTC] Persistencia: Registro de Task Definition Docker Malicioso
      |
[01:45 UTC] Anti-Forensics: Intento de DeleteTrail (Bloqueado por SCP)
      |
[01:50 UTC] Canal C2 Alterno: Trojan:EC2/DNSDataExfiltration
```

1. **Velocidad y Volumen Extremo de Exfiltración:**
   - S3: 387 llamadas `s3:GetObject` en 8 minutos (48.3 req/min) con descarga de **45.7 GB** (~95.2 MB/s).
   - Red: Conexión constante de 38 minutos desde `10.0.2.45:39201` transfiriendo **~49 GB** por el puerto 443 directamente hacia la IP del nodo Tor.
2. **Ventana Horaria Estratégica:**
   - Actividad iniciada a las **00:00 UTC** (madrugada en operaciones locales de flota), diseñada para evadir la supervisión de turnos regulares de soporte.
3. **Evasión y Destrucción de Evidencia (Anti-Forensics):**
   - El atacante intentó ejecutar `cloudtrail:DeleteTrail` para borrar el historial forense y dificultar el cálculo del alcance de la brecha. Afortunadamente, una Service Control Policy (SCP) en la raíz de AWS Organizations impidió la eliminación.
4. **Técnica de Canal Encubierto (DNS Data Exfiltration):**
   - Tras notar el posible bloqueo o saturación de ancho de banda, la instancia `i-0abc1234def56789` comenzó a exfiltrar registros comprimidos mediante consultas DNS codificadas hacia servidores DNS autoritativos controlados por el atacante.

---

## 4. Despliegue de GuardDuty Threat Intel Set

Para que Amazon GuardDuty genere alertas inmediatas de severidad CRÍTICA ante cualquier comunicación con la infraestructura del atacante, se generó el archivo `guardduty_threat_intel_set.txt`.

### Opción A: Carga y Activación vía AWS CLI

```bash
# 1. Subir la lista de IPs al bucket de auditoría inmutable
aws s3 cp detection/threat-intel/guardduty_threat_intel_set.txt \
  s3://fleetsec-production-123456789012-audit/threat-intel/guardduty_threat_intel_set.txt

# 2. Obtener el Detector ID activo en la región
DETECTOR_ID=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)

# 3. Crear y activar el ThreatIntelSet en GuardDuty
aws guardduty create-threat-intel-set \
  --detector-id "$DETECTOR_ID" \
  --name "FleetSec-Active-Breach-Tor-C2" \
  --format TXT \
  --location "s3://fleetsec-production-123456789012-audit/threat-intel/guardduty_threat_intel_set.txt" \
  --activate
```

### Opción B: Aprovisionamiento Automatizado vía Terraform

```hcl
resource "aws_s3_object" "guardduty_threat_intel_file" {
  bucket  = aws_s3_bucket.audit.id
  key     = "threat-intel/guardduty_threat_intel_set.txt"
  source  = "${path.module}/../../detection/threat-intel/guardduty_threat_intel_set.txt"
  etag    = filemd5("${path.module}/../../detection/threat-intel/guardduty_threat_intel_set.txt")
}

resource "aws_guardduty_threat_intel_set" "active_breach_c2" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.audit.id}/${aws_s3_object.guardduty_threat_intel_file.key}"
  name        = "FleetSec-Breach-Tor-C2-ThreatSet"

  depends_on = [aws_s3_object.guardduty_threat_intel_file]
}
```
