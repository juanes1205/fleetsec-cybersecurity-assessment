# Playbook de Contención en Caliente y Preservación Forense (AWS CLI)

**Código de Incidente:** `IR-2026-FLEETSEC-001`  
**Severidad:** `CRÍTICA` (Breach activo con exfiltración masiva en curso)  
**Objetivo Operativo:** Detener de inmediato la exfiltración de datos, neutralizar el acceso del atacante, revocar credenciales comprometidas, aislar la infraestructura vulnerada y asegurar la cadena de custodia forense sin destruir evidencia volátil.

---

## Parámetros Globales de Ejecución

```bash
# Variables del incidente identificadas en T+02:00
export AWS_REGION="us-east-1"
export COMPROMISED_USER="svc-monitoring"
export COMPROMISED_INSTANCE="i-0abc1234def56789"
export TARGET_BUCKET="fleetpay-prod-drivers"
export AUDIT_BUCKET="fleetsec-production-123456789012-audit"
export MALICIOUS_IMAGE="docker.io/attacker/exfil:latest"
export ATTACKER_IP="185.220.101.22"
export INCIDENT_TAG="IR-20261128-01"
```

---

## Paso 1: Revocación Inmediata de Credenciales Programáticas (Access Keys)

### 1.1 Ejecución de Contención
Identificar y desactivar de inmediato cualquier Access Key activa perteneciente al usuario `svc-monitoring`:

```bash
# Listar llaves de acceso asociadas al usuario
aws iam list-access-keys --user-name "$COMPROMISED_USER" --output table

# Para cada AccessKeyId identificada (ej. AKIAIOSFODNN7EXAMPLE), pasarla a estado 'Inactive'
for KEY_ID in $(aws iam list-access-keys --user-name "$COMPROMISED_USER" --query "AccessKeyMetadata[?Status=='Active'].AccessKeyId" --output text); do
    echo "[!] Desactivando clave de acceso activa: $KEY_ID"
    aws iam update-access-key \
        --user-name "$COMPROMISED_USER" \
        --access-key-id "$KEY_ID" \
        --status Inactive
done
```

### 1.2 Verificación
```bash
aws iam list-access-keys --user-name "$COMPROMISED_USER" --query "AccessKeyMetadata[*].[AccessKeyId,Status]" --output table
# Salida esperada: Todas las claves deben figurar como 'Inactive'.
```

### 1.3 Procedimiento de Rollback
En caso de reactivación autorizada tras saneamiento de credenciales:
```bash
aws iam update-access-key \
    --user-name "$COMPROMISED_USER" \
    --access-key-id "$KEY_ID" \
    --status Active
```

---

## Paso 2: Desactivación de Acceso Interactivo a Consola y Despojo de Privilegios

### 2.1 Ejecución de Contención
El atacante habilitó consola interactiva (`iam:CreateLoginProfile`) y se auto-adjudicó `AdministratorAccess`. Se elimina el login profile, se desasocia la política administrativa y se impone un límite de denegación absoluta:

```bash
# 1. Eliminar acceso a la consola de AWS
aws iam delete-login-profile --user-name "$COMPROMISED_USER"

# 2. Desasociar la política de Administrador
aws iam detach-user-policy \
    --user-name "$COMPROMISED_USER" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# 3. Aplicar política restrictiva inline de Denegación Total (DenyAll)
cat << 'EOF' > /tmp/incident_deny_all.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IncidentEmergencyQuarantineDenyAll",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-user-policy \
    --user-name "$COMPROMISED_USER" \
    --policy-name "IncidentEmergencyDenyAll" \
    --policy-document file:///tmp/incident_deny_all.json
```

### 2.2 Verificación
```bash
# Validar que el login profile no exista
aws iam get-login-profile --user-name "$COMPROMISED_USER" 2>&1 | grep -q "NoSuchEntity" && echo "[OK] Login profile eliminado"

# Validar políticas adjuntas
aws iam list-attached-user-policies --user-name "$COMPROMISED_USER"
aws iam list-user-policies --user-name "$COMPROMISED_USER"
```

### 2.3 Procedimiento de Rollback
```bash
# Eliminar política de denegación total
aws iam delete-user-policy \
    --user-name "$COMPROMISED_USER" \
    --policy-name "IncidentEmergencyDenyAll"

# Reasociar política legítima de monitoreo previamente autorizada
aws iam attach-user-policy \
    --user-name "$COMPROMISED_USER" \
    --policy-arn "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
```

---

## Paso 3: Invalidación y Revocación de Sesiones Activas (STS / Console Tokens)

### 3.1 Ejecución de Contención
La eliminación del Login Profile no destruye de inmediato las cookies de sesión activa o tokens temporales ya emitidos. Se invalida cualquier sesión activa mediante una política con condición temporal `aws:CurrentTime`:

```bash
REVOCATION_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat << EOF > /tmp/revoke_sessions.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RevokeAllPriorSessions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:CurrentTime": "$REVOCATION_TIMESTAMP"
        }
      }
    }
  ]
}
EOF

aws iam put-user-policy \
    --user-name "$COMPROMISED_USER" \
    --policy-name "RevokeSessionsPolicy" \
    --policy-document file:///tmp/revoke_sessions.json
```

### 3.2 Verificación
Cualquier llamada subsecuente realizada con tokens de sesión preexistentes será rechazada con `AccessDenied` / `ExplicitDeny`.

### 3.3 Procedimiento de Rollback
```bash
aws iam delete-user-policy \
    --user-name "$COMPROMISED_USER" \
    --policy-name "RevokeSessionsPolicy"
```

---

## Paso 4: Aislamiento de Red de la Instancia EC2 Comprometida (`i-0abc1234def56789`)

### 4.1 Ejecución de Contención
La instancia `i-0abc1234def56789` está ejecutando un troyano con canal encubierto DNS (`Trojan:EC2/DNSDataExfiltration`). Se aísla a nivel de red reemplazando sus Security Groups por un SG de cuarentena sin reglas entrantes ni salientes (aislamiento total en vivo sin apagar la máquina para no perder memoria RAM volátil):

```bash
# 1. Obtener la VPC y los grupos de seguridad actuales de la instancia para el backup de rollback
VPC_ID=$(aws ec2 describe-instances \
    --instance-ids "$COMPROMISED_INSTANCE" \
    --query "Reservations[0].Instances[0].VpcId" \
    --output text)

ORIGINAL_SGS=$(aws ec2 describe-instances \
    --instance-ids "$COMPROMISED_INSTANCE" \
    --query "Reservations[0].Instances[0].SecurityGroups[*].GroupId" \
    --output text)

echo "[i] Guardando SG originales para rollback: $ORIGINAL_SGS"

# 2. Crear Security Group de Cuarentena (Zero Ingress, Zero Egress)
QUARANTINE_SG=$(aws ec2 create-security-group \
    --group-name "fleetsec-quarantine-sg-$INCIDENT_TAG" \
    --description "Aislamiento Forense Estricto - Incidente $INCIDENT_TAG" \
    --vpc-id "$VPC_ID" \
    --query "GroupId" \
    --output text)

# Eliminar la regla de salida por defecto (0.0.0.0/0) creada automáticamente por AWS
aws ec2 revoke-security-group-egress \
    --group-id "$QUARANTINE_SG" \
    --protocol "-1" \
    --cidr "0.0.0.0/0"

# 3. Aplicar el grupo de cuarentena de forma exclusiva a la instancia
aws ec2 modify-instance-attribute \
    --instance-id "$COMPROMISED_INSTANCE" \
    --groups "$QUARANTINE_SG"

# 4. Desregistrar y anular la Task Definition maliciosa en ECS
TASK_DEF_ARN=$(aws ecs list-task-definitions \
    --family-prefix "exfil" \
    --query "taskDefinitionArns[0]" \
    --output text)

if [ "$TASK_DEF_ARN" != "None" ] && [ -n "$TASK_DEF_ARN" ]; then
    echo "[!] Desregistrando definicion de tarea maliciosa: $TASK_DEF_ARN"
    aws ecs deregister-task-definition --task-definition "$TASK_DEF_ARN"
fi
```

### 4.2 Verificación
```bash
# Validar que el único Security Group asignado sea el de cuarentena
aws ec2 describe-instances \
    --instance-ids "$COMPROMISED_INSTANCE" \
    --query "Reservations[0].Instances[0].SecurityGroups[*].[GroupId,GroupName]" \
    --output table

# Validar que no existan reglas de entrada ni salida
aws ec2 describe-security-group-rules \
    --filters "Name=group-id,Values=$QUARANTINE_SG" \
    --output table
```

### 4.3 Procedimiento de Rollback
Si la instancia requiere reincorporarse al clúster tras análisis forense y desinfección:
```bash
# Restaurar los Security Groups originales
aws ec2 modify-instance-attribute \
    --instance-id "$COMPROMISED_INSTANCE" \
    --groups $ORIGINAL_SGS

# Eliminar el grupo de cuarentena
aws ec2 delete-security-group --group-id "$QUARANTINE_SG"
```

---

## Paso 5: Preservación de Evidencia Forense (EBS Snapshots y Logs Write-Once)

### 5.1 Ejecución de Contención
Para garantizar la admisibilidad jurídica ante la Superintendencia de Industria y Comercio (SIC) y autoridades judiciales, la evidencia debe preservarse sin alteración:

```bash
# 1. Obtener todos los IDs de volumen EBS adjuntos a la instancia comprometida
VOLUME_IDS=$(aws ec2 describe-instances \
    --instance-ids "$COMPROMISED_INSTANCE" \
    --query "Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId" \
    --output text)

# 2. Tomar snapshots forenses inmediatos de cada volumen
for VOL in $VOLUME_IDS; do
    echo "[+] Creando snapshot forense para el volumen: $VOL"
    aws ec2 create-snapshot \
        --volume-id "$VOL" \
        --description "Evidencia Forense Inmutable - Incidente $INCIDENT_TAG - Vol $VOL" \
        --tag-specifications "ResourceType=snapshot,Tags=[{Key=IncidentId,Value=$INCIDENT_TAG},{Key=EvidenceState,Value=ForensicPreservation},{Key=ChainOfCustody,Value=Active}]"
done

# 3. Exportar logs de CloudTrail de la ventana de ataque a S3 inmutable (Object Lock COMPLIANCE)
TWO_HOURS_AGO_MS=$(python -c 'import time; print(int((time.time() - 7200) * 1000))' 2>/dev/null || date -d "2 hours ago" +%s000 2>/dev/null || echo "1700000000000")
NOW_MS=$(python -c 'import time; print(int(time.time() * 1000))' 2>/dev/null || date +%s000 2>/dev/null || echo "1700007200000")

aws logs create-export-task \
    --task-name "ForensicExport-CloudTrail-$INCIDENT_TAG" \
    --log-group-name "/fleetsec/production/cloudtrail" \
    --from "$TWO_HOURS_AGO_MS" \
    --to "$NOW_MS" \
    --destination "$AUDIT_BUCKET" \
    --destination-prefix "forensics/$INCIDENT_TAG/cloudtrail"

# 4. Exportar VPC Flow Logs de la ventana de ataque
aws logs create-export-task \
    --task-name "ForensicExport-VPCFlow-$INCIDENT_TAG" \
    --log-group-name "/fleetsec/production/vpc-flow-logs" \
    --from "$TWO_HOURS_AGO_MS" \
    --to "$NOW_MS" \
    --destination "$AUDIT_BUCKET" \
    --destination-prefix "forensics/$INCIDENT_TAG/vpcflowlogs"
```

### 5.2 Verificación
```bash
# Validar estado de los snapshots
aws ec2 describe-snapshots \
    --filters "Name=tag:IncidentId,Values=$INCIDENT_TAG" \
    --query "Snapshots[*].[SnapshotId,VolumeId,State,Progress]" \
    --output table

# Validar estado de las tareas de exportación de logs
aws logs describe-export-tasks \
    --query "exportTasks[?destination=='$AUDIT_BUCKET'].[taskId,taskName,status.code]" \
    --output table
```

### 5.3 Procedimiento de Rollback
La preservación forense es una operación de solo lectura (no destructiva y sin impacto en servicios de producción). Una vez concluido el proceso legal y vencidos los periodos de retención legal de 3 a 5 años, los snapshots y copias forenses podrán purgarse de acuerdo con la política de retención de datos corporativa.
