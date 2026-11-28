# FleetSec S.A.S. — Incident Response & Forensics Hub

Este directorio contiene el conjunto completo de artefactos de **Respuesta a Incidentes (IR), Preservación Forense, Causa Raíz (RCA) y Gobierno Regulatorio** desarrollados para mitigar la brecha de seguridad y cumplir con las exigencias de la **Ley 1581 de 2012** e **ISO 27001:2022**.

---

## Estructura de Artefactos de Respuesta a Incidentes

| Documento | Alcance y Propósito | Audiencia | Estado |
|---|---|---|:---:|
| **1. Playbook de Contención CLI**<br>[`containment-playbook.md`](containment-playbook.md) | Comandos AWS CLI exactos paso a paso con procedimientos de rollback para (1) revocar credenciales, (2) desactivar cuenta IAM, (3) revocar sesiones, (4) aislar EC2 a SG cuarentena y (5) preservar evidencia forense con Object Lock. | Equipo de Seguridad / Cloud SecOps | **EJECUTADO / ACTIVO** |
| **2. Mapeo MITRE ATT&CK v14**<br>[`mitre-attack-mapping.md`](mitre-attack-mapping.md) | Mapeo detallado de 8 técnicas de la matriz Cloud (T1078.004, T1098, T1098.001, T1530, T1562.008, T1053.007, T1048.003, T1071.004) con controles de mitigación. | Ingenieros de Detección / Auditores | **COMPLETO** |
| **3. Análisis de Causa Raíz (RCA)**<br>[`root-cause-analysis.md`](root-cause-analysis.md) | Justificación técnica del vector inicial, diagrama cronológico del attack path de extremo a extremo y diagnóstico de fallos en controles preexistentes (5 Whys). | Liderazgo Técnico / Arquitectura | **COMPLETO** |
| **4. Resumen Ejecutivo para el CEO**<br>[`ceo-executive-summary.md`](ceo-executive-summary.md) | Resumen no técnico de 1 página: hechos ocurridos, 45.7 GB de datos expuestos (~60,000 conductores), plazo perentorio de 15 días hábiles ante la SIC (Ley 1581) y 3 decisiones inmediatas. | CEO / Junta Directiva / Legal | **LISTO PARA FIRMA** |
| **5. Plan de Remediación Post-Incidente**<br>[`post-incident-remediation-plan.md`](post-incident-remediation-plan.md) | Plan de acción priorizado en P1 (0–7 d), P2 (8–30 d) y P3 (31–90 d) con esfuerzo estimado en horas, áreas responsables y métricas de éxito. | Comité de Crisis / PMO | **PLANIFICADO** |

---

## Relación con Detección e Inteligencia de Amenazas

Este módulo opera en sinergia con el directorio [`../detection/`](../detection/):
* **IOCs y Enriquecimiento:** [`../detection/threat-intel/iocs_enrichment.md`](../detection/threat-intel/iocs_enrichment.md)
* **Threat Intel Set de GuardDuty:** [`../detection/threat-intel/guardduty_threat_intel_set.txt`](../detection/threat-intel/guardduty_threat_intel_set.txt)
* **Reglas de Detección Sigma:** [`../detection/sigma/`](../detection/sigma/)
