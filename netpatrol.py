import os
import re

LOG_FILE = "auth_sim.log"

def analizar_logs(ruta_archivo):
		if not os.path.exists(ruta_archivo):
			print(f"[ERROR] No se encontró el archivo: {ruta_archivo}")
			return

		patron_ip = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
		ips_sospechosas = []
		conteo_ips ={}

		with open(ruta_archivo, 'r') as archivo:
			lineas = archivo.readlines()

		print(f"[*] Analizando {len(lineas)} eventos en busca de intrusiones...")
		print("-" * 50)

		for linea in lineas:
			if "Failed password" in linea:
				coincidencia = re.search(patron_ip, linea)
				if coincidencia:
					ip = coincidencia.group()
					ips_sospechosas.append(ip)
					if ip in conteo_ips:
						conteo_ips[ip] +=1
					else:
						conteo_ips[ip] = 1

		print("-" * 50)
		print(f"[*] Resumen: Se detectaron {len(ips_sospechosas)} intentos anómalos.")

		print("\n[*] Detalle de atacantes:")
		for ip, cantidad in conteo_ips.items():
			print(f"	- IP: {ip} | Intentos bloqueados: {cantidad}")
		return conteo_ips

def generar_mitigacion(diccionario_ips):
		with open("block_ips.sh", "w") as archivo_sh:
			archivo_sh.write("#!/bin/bash\n")
			for ip, cantidad in diccionario_ips.items():
				comando = f"iptables -A INPUT -s {ip} -j DROP\n"

				archivo_sh.write(comando)

print(f"[*] Archivo de mitigación 'block_ips.sh' generado exitosamente")

if __name__ == "__main__":
	diccionario_resultado = analizar_logs(LOG_FILE)
	if diccionario_resultado:
			generar_mitigacion(diccionario_resultado)
