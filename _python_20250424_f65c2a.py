import os
import yara
import time
import hashlib
import requests
import psutil
import pefile
import re
import json
import subprocess
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ================= CONFIGURACIÓN INICIAL =================
YARA_RULES_URL = "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_AZORULT.yar"
CUCKOO_SANDBOX_PATH = "C:\\Cuckoo\\bin\\python.exe"  # Ajustar ruta
VT_API_KEY = "TU_API_DE_VIRUSTOTAL"  # Opcional: https://www.virustotal.com/

# ================= FUNCIONES BÁSICAS =================
def update_yara_rules():
    """Descarga reglas YARA actualizadas desde GitHub."""
    try:
        response = requests.get(YARA_RULES_URL)
        with open("malware_rules.yar", "wb") as f:
            f.write(response.content)
        return yara.compile(filepath="malware_rules.yar")
    except Exception as e:
        print(f"Error al actualizar YARA: {e}")
        backup_rule = 'rule Backup { strings: $a = {6A 40} condition: $a }'
        return yara.compile(source=backup_rule)

def get_file_hash(file_path):
    """Calcula el hash SHA-256 de un archivo."""
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# ================= DETECCIÓN AVANZADA =================
def heuristic_analysis(file_path):
    """Busca patrones sospechosos en el contenido."""
    suspicious_keywords = [
        "CreateRemoteThread", "keylogger", 
        "ransom", "http://", "cmd.exe"
    ]
    try:
        with open(file_path, "rb") as f:
            content = f.read().decode(errors="ignore").lower()
            return any(keyword in content for keyword in suspicious_keywords)
    except:
        return False

def analyze_pe(file_path):
    """Extrae características de archivos PE (Windows)."""
    try:
        pe = pefile.PE(file_path)
        return {
            "sections": len(pe.sections),
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "imports": [entry.name.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
        }
    except:
        return None

# ================= GESTIÓN DE RECURSOS =================
def adjust_scanning_intensity(file_path):
    """Ajusta el análisis según el tipo de archivo."""
    low_risk_ext = ['.txt', '.jpg', '.mp3']
    if any(file_path.endswith(ext) for ext in low_risk_ext):
        return "low"
    return "high" if file_path.endswith(('.exe', '.dll')) else "medium"

# ================= USB PROTECTION =================
def scan_usb():
    """Escanea dispositivos USB conectados."""
    for device in psutil.disk_partitions():
        if 'removable' in device.opts:
            print(f"\n🔍 Analizando USB: {device.device}")
            for root, _, files in os.walk(device.mountpoint):
                for file in files:
                    file_path = os.path.join(root, file)
                    if scan_file(file_path):
                        print(f"🚨 Amenaza encontrada: {file_path}")

# ================= MONITORIZACIÓN EN TIEMPO REAL =================
class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            print(f"\n📂 Archivo modificado: {event.src_path}")
            scan_file(event.src_path)

def start_monitoring(path="C:\\"):
    observer = Observer()
    observer.schedule(FileChangeHandler(), path, recursive=True)
    observer.start()
    print(f"👁️ Monitorizando {path}...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ================= FUNCIÓN PRINCIPAL DE ESCANEO =================
def scan_file(file_path):
    """Función principal que orquesta todo el análisis."""
    try:
        # 1. Verificación básica
        if not os.path.exists(file_path):
            return False

        # 2. Análisis según intensidad
        intensity = adjust_scanning_intensity(file_path)
        if intensity == "low":
            return False  # Omite archivos de bajo riesgo

        # 3. Detección por YARA
        rules = update_yara_rules()
        matches = rules.match(file_path)
        if matches:
            print(f"⚠️ Detectado por YARA: {file_path}")

        # 4. Análisis heurístico
        if heuristic_analysis(file_path):
            print(f"🔍 Comportamiento sospechoso: {file_path}")

        # 5. Análisis PE (para ejecutables)
        if file_path.endswith(('.exe', '.dll')):
            pe_info = analyze_pe(file_path)
            if pe_info and "CreateRemoteThread" in str(pe_info["imports"]):
                print(f"🛑 Troyano potencial: {file_path}")

        # 6. Sandboxing (Opcional)
        if intensity == "high" and os.path.exists(CUCKOO_SANDBOX_PATH):
            subprocess.run([CUCKOO_SANDBOX_PATH, "submit", "--quick", file_path])

        return bool(matches)

    except Exception as e:
        print(f"Error al escanear {file_path}: {e}")
        return False

# ================= INTERFAZ DE USUARIO =================
def main_menu():
    print("\n" + "="*50)
    print("🛡️ ANTIVIRUS AVANZADO - MENÚ PRINCIPAL")
    print("="*50)
    print("1. Escanear archivo o carpeta")
    print("2. Monitorizar cambios en tiempo real")
    print("3. Analizar dispositivos USB")
    print("4. Salir")
    
    choice = input("Seleccione una opción (1-4): ")
    return choice

# ================= EJECUCIÓN PRINCIPAL =================
if __name__ == "__main__":
    while True:
        option = main_menu()
        if option == "1":
            target = input("Introduzca la ruta a escanear: ")
            if os.path.isdir(target):
                for root, _, files in os.walk(target):
                    for file in files:
                        scan_file(os.path.join(root, file))
            else:
                scan_file(target)
        elif option == "2":
            path = input("Directorio a monitorizar (ej. C:\\): ")
            start_monitoring(path)
        elif option == "3":
            scan_usb()
        elif option == "4":
            print("Saliendo del programa...")
            break
        else:
            print("Opción no válida. Intente nuevamente.")