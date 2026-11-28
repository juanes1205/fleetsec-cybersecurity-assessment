# FleetSec S.A.S. — Threat Detection & Intelligence Hub

Este directorio contiene los artefactos de **Inteligencia de Amenazas** y **Reglas de Detección (Sigma)** desarrollados en respuesta al incidente de seguridad y exfiltración de telemetría de FleetSec S.A.S.

---

## 1. Threat Intelligence & Indicadores de Compromiso (IOCs)

* **Reporte de Enriquecimiento:** [`threat-intel/iocs_enrichment.md`](threat-intel/iocs_enrichment.md)
  * Catalogación exhaustiva de IOCs: IP atacante (`185.220.101.22`), IP interna (`10.0.2.45`), usuario IAM (`svc-monitoring`), imagen maliciosa (`docker.io/attacker/exfil:latest`), bucket exfiltrado (`fleetpay-prod-drivers`), llave KMS (`prod-data-key`), instancia EC2 (`i-0abc1234def56789`).
  * Enriquecimiento con Geolocalización, ASN (AS 213151 - Tor Exit Node), AbuseIPDB (100% score), VirusTotal, Shodan, feeds MISP y AlienVault OTX.
  * Análisis de volumen, velocidad (45.7 GB / 8 min) y ventana horaria nocturna (00:00 UTC).
* **Threat Intel Set para GuardDuty:** [`threat-intel/guardduty_threat_intel_set.txt`](threat-intel/guardduty_threat_intel_set.txt)
  * Procedimiento documentado para carga y activación mediante AWS CLI y Terraform.

---

## 2. Reglas de Detección Sigma (YAML)

Todas las reglas siguen el estándar oficial de **Sigma Specification v1.0.1** y están listas para conversión a SIEM (Splunk, Elastic, Sentinel, CloudWatch Logs Insights):

| Regla | Archivo | Logsource | MITRE ATT&CK | Nivel | Descripción |
|---|---|---|---|:---:|---|
| **Regla 1** | [`sigma/rule1_cloudtrail_admin_escalation_offhours.yml`](sigma/rule1_cloudtrail_admin_escalation_offhours.yml) | CloudTrail (AWS) | T1098, T1078.004 | **HIGH** | Adjunción de política `AdministratorAccess` a usuario o rol fuera de horario laboral (00:00–06:00 UTC). |
| **Regla 2** | [`sigma/rule2_cloudtrail_deletetrail_antiforensics.yml`](sigma/rule2_cloudtrail_deletetrail_antiforensics.yml) | CloudTrail (AWS) | T1562.008 | **CRITICAL** | Intento de eliminación o desactivación de CloudTrail (`DeleteTrail` / `StopLogging`) como técnica anti-forense. |
| **Regla 3** | [`sigma/rule3_app_sqli_query_parameters.yml`](sigma/rule3_app_sqli_query_parameters.yml) | Application Logs | T1190 / CWE-89 | **HIGH** | Detección de patrones SQL Injection clásicos y basados en tiempo en parámetros HTTP. |
| **Regla 4 (Bonus)** | [`sigma/rule4_bonus_s3_bulk_getobject_anomaly.yml`](sigma/rule4_bonus_s3_bulk_getobject_anomaly.yml) | S3 Access / CloudTrail | T1530 | **HIGH** | Descargas masivas anómalas en S3 (>100 llamadas `GetObject` / 5 min desde el mismo IAM principal). |
