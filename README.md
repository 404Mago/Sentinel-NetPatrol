# Sentinel-NetPatrol: Automated SSH Log Analyzer & Mitigation

**Rol/Nivel:** Trainee / Junior Security-Sysadmin Project  
**Stack:** Python 3 (Regex, I/O Operations), Linux Bash, `iptables`.

## Problema
Los servidores expuestos a internet sufren ataques de fuerza bruta por SSH constantemente. Analizar los logs de autenticación (`/var/log/auth.log`) de forma manual es ineficiente errático.

## MVP
Un script ligero en Python que ingesta logs del sistema, utiliza Regex para aislar aquellas direcciones IP con intentos fallidos y automatiza la respuesta a incidentes generando un script de Bash ('block_ips.sh') con reglas de bloqueo listas para 'iptables'.

## ¿Cómo Funciona?
1. **Ingesta:** Lee un archivo de logs estándar de Linux.
2. **Detección:** Extrae las IPs atacantes y contabiliza la frecuencia utilizando diccionarios.
3. **Mitigación:** Genera automáticamente reglas de firewall para aislar amenazas que superen el umbral de tolerancia.

## Uso Rápido
```bash
# 1. Ejecutar el análisis
python netpatrol.py

# 2. Revisar y aplicar la mitigación (Requiere privilegios root en producción)
cat block_ips.sh
sudo bash block_ips.sh
