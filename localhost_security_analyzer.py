import sys
import json
import socket
import subprocess
import psutil
import threading
import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import re
import time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QPushButton,
    QProgressBar, QLabel, QFileDialog, QMessageBox, QInputDialog,
    QComboBox, QSpinBox, QCheckBox, QDialog, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtChart import QChart, QChartView, QPieSeries, QPieSlice
import threading
import requests
from urllib.parse import urlparse

class ForensicAnalyzer(QThread):
    """Analizador forense digital avanzado"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'ports': [],
            'processes': [],
            'network_connections': [],
            'suspicious_activities': [],
            'file_hashes': [],
            'registry_scan': [],
            'dns_queries': [],
            'malware_indicators': [],
            'exfiltration_risks': [],
            'summary': {}
        }
        self.malware_signatures = self._load_malware_signatures()
        self.suspicious_ports = {445, 139, 135, 3389, 4444, 5555, 6666}
        self.known_malware_processes = {
            'mimikatz', 'psexec', 'nmap', 'wireshark', 'tcpdump',
            'putty', 'filezilla', 'winrar', 'unrar', 'winscp'
        }
    
    def _load_malware_signatures(self):
        """Carga firmas de malware conocidas"""
        return {
            'wannacry': ['wcry', 'wncry', 'wnry', '2017m'],
            'emotet': ['emotet', 'heodo', 'botnet'],
            'trickbot': ['trickbot', 'tricker'],
            'mirai': ['mirai', 'botnet_mirai'],
            'ransomware': ['encrypt', 'crypt', 'ransom'],
            'trojan': ['trojan', 'backdoor', 'remote'],
            'keylogger': ['keylog', 'keystroke', 'logger'],
            'spyware': ['spy', 'monitor', 'tracker']
        }
    
    def run(self):
        """Ejecuta el análisis completo"""
        try:
            self.progress.emit("🔍 Iniciando análisis forense...")
            
            self.progress.emit("📊 Analizando puertos abiertos...")
            self._analyze_ports()
            
            self.progress.emit("⚙️ Analizando procesos en ejecución...")
            self._analyze_processes()
            
            self.progress.emit("🌐 Analizando conexiones de red...")
            self._analyze_network_connections()
            
            self.progress.emit("⚠️ Detectando actividades sospechosas...")
            self._detect_suspicious_activities()
            
            self.progress.emit("🔐 Realizando hashing de archivos críticos...")
            self._hash_critical_files()
            
            self.progress.emit("📝 Analizando registro de Windows...")
            self._analyze_registry()
            
            self.progress.emit("🌐 Analizando queries DNS...")
            self._analyze_dns_queries()
            
            self.progress.emit("🦠 Buscando indicadores de malware...")
            self._detect_malware_indicators()
            
            self.progress.emit("📤 Analizando riesgos de exfiltración...")
            self._analyze_exfiltration_risks()
            
            self.progress.emit("✅ Análisis completado")
            self.finished.emit(self.results)
            
        except Exception as e:
            self.progress.emit(f"❌ Error: {str(e)}")
    
    def _analyze_ports(self):
        """Analiza puertos abiertos"""
        try:
            connections = psutil.net_connections()
            port_data = defaultdict(list)
            
            for conn in connections:
                if conn.laddr and conn.laddr.port > 0:
                    port_num = conn.laddr.port
                    state = conn.status
                    try:
                        service = socket.getservbyport(port_num)
                    except:
                        service = "Unknown"
                    
                    port_info = {
                        'port': port_num,
                        'service': service,
                        'state': state,
                        'ip': conn.laddr.ip if conn.laddr else 'N/A',
                        'pid': conn.pid if conn.pid else 'N/A',
                        'suspicious': port_num in self.suspicious_ports
                    }
                    port_data[port_num].append(port_info)
            
            self.results['ports'] = list(port_data.values())
            
        except Exception as e:
            self.progress.emit(f"⚠️ Error analizando puertos: {str(e)}")
    
    def _analyze_processes(self):
        """Analiza procesos en ejecución"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cwd']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'cwd', 'create_time'])
                    
                    # Detectar procesos sospechosos
                    suspicious = False
                    suspicious_reason = []
                    
                    name_lower = pinfo['name'].lower()
                    if any(mal in name_lower for mal in self.known_malware_processes):
                        suspicious = True
                        suspicious_reason.append("Nombre de proceso conocido como malware")
                    
                    if pinfo.get('exe', '').lower() in ['c:\\temp', 'c:\\windows\\temp', 'c:\\appdata\\local\\temp']:
                        suspicious = True
                        suspicious_reason.append("Ejecutable en carpeta temporal")
                    
                    process_info = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo.get('exe', 'N/A'),
                        'cmdline': ' '.join(pinfo.get('cmdline', [])) if pinfo.get('cmdline') else 'N/A',
                        'cwd': pinfo.get('cwd', 'N/A'),
                        'create_time': datetime.fromtimestamp(pinfo['create_time']).isoformat(),
                        'suspicious': suspicious,
                        'reasons': suspicious_reason
                    }
                    
                    self.results['processes'].append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        except Exception as e:
            self.progress.emit(f"⚠️ Error analizando procesos: {str(e)}")
    
    def _analyze_network_connections(self):
        """Analiza conexiones de red activas"""
        try:
            suspicious_ips = set()
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    # Obtener información del proceso
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else 'Unknown'
                    except:
                        proc_name = 'Unknown'
                    
                    conn_info = {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                        'status': conn.status,
                        'process': proc_name,
                        'pid': conn.pid if conn.pid else 'N/A',
                        'type': conn.type,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Detectar IPs sospechosas
                    if conn.raddr and self._is_suspicious_ip(conn.raddr.ip):
                        suspicious_ips.add(conn.raddr.ip)
                        conn_info['suspicious'] = True
                    
                    self.results['network_connections'].append(conn_info)
            
        except Exception as e:
            self.progress.emit(f"⚠️ Error analizando conexiones de red: {str(e)}")
    
    def _is_suspicious_ip(self, ip):
        """Verifica si una IP es sospechosa"""
        # IPs privadas generalmente son seguras
        private_ranges = [
            '127.', '192.168.', '10.', '172.'
        ]
        return not any(ip.startswith(r) for r in private_ranges)
    
    def _detect_suspicious_activities(self):
        """Detecta actividades sospechosas"""
        suspicious = []
        
        # Detectar procesos con permisos elevados inusuales
        for proc_info in self.results['processes']:
            if proc_info['suspicious']:
                suspicious.append({
                    'type': 'Proceso Sospechoso',
                    'target': proc_info['name'],
                    'details': proc_info['reasons'],
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat()
                })
        
        # Detectar conexiones a IPs externas
        for conn in self.results['network_connections']:
            if 'remote_addr' in conn and ':' in conn['remote_addr']:
                ip = conn['remote_addr'].split(':')[0]
                if not any(ip.startswith(r) for r in ['127.', '192.168.', '10.', '172.']):
                    suspicious.append({
                        'type': 'Conexión Externa',
                        'target': conn['remote_addr'],
                        'process': conn['process'],
                        'severity': 'MEDIUM',
                        'timestamp': datetime.now().isoformat()
                    })
        
        self.results['suspicious_activities'] = suspicious
    
    def _hash_critical_files(self):
        """Calcula hash de archivos críticos"""
        critical_paths = [
            'C:\\Windows\\System32\\cmd.exe',
            'C:\\Windows\\System32\\powershell.exe',
            'C:\\Windows\\System32\\services.exe',
            'C:\\Windows\\System32\\svchost.exe',
            'C:\\Windows\\System32\\registry.exe'
        ]
        
        for path in critical_paths:
            if os.path.exists(path):
                try:
                    md5_hash = self._calculate_hash(path, 'md5')
                    sha256_hash = self._calculate_hash(path, 'sha256')
                    
                    self.results['file_hashes'].append({
                        'path': path,
                        'md5': md5_hash,
                        'sha256': sha256_hash,
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    self.progress.emit(f"⚠️ Error hasheando {path}: {str(e)}")
    
    def _calculate_hash(self, filepath, hash_type='sha256'):
        """Calcula hash de un archivo"""
        hash_obj = hashlib.new(hash_type)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def _analyze_registry(self):
        """Analiza el registro de Windows en busca de anomalías"""
        try:
            suspicious_keys = [
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            ]
            
            for key in suspicious_keys:
                try:
                    result = subprocess.run(
                        ['reg', 'query', key],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if line.strip() and not line.startswith('HKEY'):
                                self.results['registry_scan'].append({
                                    'key': key,
                                    'entry': line.strip(),
                                    'timestamp': datetime.now().isoformat()
                                })
                except Exception as e:
                    pass
        except Exception as e:
            self.progress.emit(f"⚠️ Error analizando registro: {str(e)}")
    
    def _analyze_dns_queries(self):
        """Analiza queries DNS"""
        try:
            # Intentar leer caché DNS
            result = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'Record Name' in line:
                        dns_info = {
                            'query': line.split(':', 1)[1].strip() if ':' in line else '',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.results['dns_queries'].append(dns_info)
        except Exception as e:
            self.progress.emit(f"⚠️ Error analizando DNS: {str(e)}")
    
    def _detect_malware_indicators(self):
        """Detecta indicadores de malware conocidos"""
        indicators = []
        
        # Buscar en nombres de procesos
        for proc_info in self.results['processes']:
            proc_name_lower = proc_info['name'].lower()
            for malware_type, signatures in self.malware_signatures.items():
                if any(sig in proc_name_lower for sig in signatures):
                    indicators.append({
                        'type': 'Proceso Malware Detectado',
                        'malware_family': malware_type,
                        'target': proc_info['name'],
                        'pid': proc_info['pid'],
                        'severity': 'CRITICAL',
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Buscar en líneas de comandos
        for proc_info in self.results['processes']:
            cmdline_lower = proc_info['cmdline'].lower()
            if any(keyword in cmdline_lower for keyword in ['powershell', 'cmd', 'script']):
                if any(sig in cmdline_lower for sig in ['encrypt', 'ransom', 'delete', 'wipe']):
                    indicators.append({
                        'type': 'Actividad Ransomware Detectada',
                        'details': proc_info['cmdline'][:100],
                        'process': proc_info['name'],
                        'severity': 'CRITICAL',
                        'timestamp': datetime.now().isoformat()
                    })
        
        self.results['malware_indicators'] = indicators
    
    def _analyze_exfiltration_risks(self):
        """Analiza riesgos de exfiltración de datos"""
        risks = []
        
        # Detectar conexiones a servidores C2 conocidos
        for conn in self.results['network_connections']:
            if 'remote_addr' in conn:
                remote_ip = conn['remote_addr'].split(':')[0]
                remote_port = int(conn['remote_addr'].split(':')[1]) if ':' in conn['remote_addr'] else 0
                
                # Puertos comúnmente usados para exfiltración
                exfil_ports = {25, 53, 443, 8080, 8443, 1433, 3306, 5432}
                if remote_port in exfil_ports and not any(remote_ip.startswith(r) for r in ['127.', '192.168.', '10.', '172.']):
                    risks.append({
                        'type': 'Exfiltración Potencial',
                        'target': conn['remote_addr'],
                        'process': conn['process'],
                        'risk_level': 'MEDIUM',
                        'details': f'Conexión a puerto comúnmente usado para exfiltración',
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Detectar procesos accediendo a archivos sensibles
        for proc_info in self.results['processes']:
            cmdline_lower = proc_info['cmdline'].lower()
            sensitive_keywords = ['document', 'password', 'key', 'secret', 'credential', 'token']
            if any(keyword in cmdline_lower for keyword in sensitive_keywords):
                risks.append({
                    'type': 'Acceso a Información Sensible',
                    'process': proc_info['name'],
                    'pid': proc_info['pid'],
                    'risk_level': 'HIGH',
                    'timestamp': datetime.now().isoformat()
                })
        
        self.results['exfiltration_risks'] = risks
    
    def export_report(self, filepath):
        """Exporta reporte en JSON"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)


class SecurityAnalyzerGUI(QMainWindow):
    """Interfaz gráfica para el analizador de seguridad"""
    
    def __init__(self):
        super().__init__()
        self.analyzer = None
        self.analysis_results = None
        self.init_ui()
    
    def init_ui(self):
        """Inicializa la interfaz de usuario"""
        self.setWindowTitle("🛡️ Localhost Security Forensic Analyzer")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet(self._get_stylesheet())
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        
        # Barra de control
        control_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🔍 Iniciar Análisis Forense")
        self.scan_btn.clicked.connect(self.start_analysis)
        self.scan_btn.setStyleSheet("background-color: #2ecc71; color: white; font-weight: bold; padding: 10px;")
        control_layout.addWidget(self.scan_btn)
        
        self.export_btn = QPushButton("📊 Exportar Reporte JSON")
        self.export_btn.clicked.connect(self.export_report)
        self.export_btn.setEnabled(False)
        self.export_btn.setStyleSheet("background-color: #3498db; color: white; font-weight: bold; padding: 10px;")
        control_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ Limpiar Resultados")
        self.clear_btn.clicked.connect(self.clear_results)
        self.clear_btn.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold; padding: 10px;")
        control_layout.addWidget(self.clear_btn)
        
        main_layout.addLayout(control_layout)
        
        # Barra de progreso
        self.progress_label = QLabel("Estado: Listo")
        main_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Tabs principales
        self.tabs = QTabWidget()
        
        # Tab 1: Resumen
        self.summary_tab = QTextEdit()
        self.summary_tab.setReadOnly(True)
        self.tabs.addTab(self.summary_tab, "📋 Resumen Ejecutivo")
        
        # Tab 2: Puertos
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(5)
        self.ports_table.setHorizontalHeaderLabels(['Puerto', 'Servicio', 'Estado', 'Sospechoso', 'PID'])
        self.tabs.addTab(self.ports_table, "🔌 Puertos")
        
        # Tab 3: Procesos
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(6)
        self.processes_table.setHorizontalHeaderLabels(['PID', 'Nombre', 'Ruta', 'Sospechoso', 'Razón', 'Creación'])
        self.tabs.addTab(self.processes_table, "⚙️ Procesos")
        
        # Tab 4: Conexiones de Red
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(5)
        self.network_table.setHorizontalHeaderLabels(['Dirección Local', 'Dirección Remota', 'Estado', 'Proceso', 'PID'])
        self.tabs.addTab(self.network_table, "🌐 Conexiones Red")
        
        # Tab 5: Actividades Sospechosas
        self.suspicious_table = QTableWidget()
        self.suspicious_table.setColumnCount(4)
        self.suspicious_table.setHorizontalHeaderLabels(['Tipo', 'Objetivo', 'Severidad', 'Detalles'])
        self.tabs.addTab(self.suspicious_table, "⚠️ Actividades Sospechosas")
        
        # Tab 6: Indicadores de Malware
        self.malware_table = QTableWidget()
        self.malware_table.setColumnCount(5)
        self.malware_table.setHorizontalHeaderLabels(['Tipo', 'Familia', 'Objetivo', 'Severidad', 'PID'])
        self.tabs.addTab(self.malware_table, "🦠 Malware Detectado")
        
        # Tab 7: Riesgos de Exfiltración
        self.exfil_table = QTableWidget()
        self.exfil_table.setColumnCount(4)
        self.exfil_table.setHorizontalHeaderLabels(['Tipo', 'Objetivo', 'Nivel de Riesgo', 'Detalles'])
        self.tabs.addTab(self.exfil_table, "📤 Riesgos de Exfiltración")
        
        # Tab 8: Hashes de Archivos
        self.hashes_table = QTableWidget()
        self.hashes_table.setColumnCount(3)
        self.hashes_table.setHorizontalHeaderLabels(['Ruta del Archivo', 'MD5', 'SHA256'])
        self.tabs.addTab(self.hashes_table, "🔐 Hashes de Archivos")
        
        # Tab 9: Registro de Windows
        self.registry_table = QTableWidget()
        self.registry_table.setColumnCount(2)
        self.registry_table.setHorizontalHeaderLabels(['Clave', 'Entrada'])
        self.tabs.addTab(self.registry_table, "📝 Registro de Windows")
        
        # Tab 10: Queries DNS
        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(2)
        self.dns_table.setHorizontalHeaderLabels(['Dominio/IP', 'Tipo'])
        self.tabs.addTab(self.dns_table, "🌐 DNS")
        
        # Tab 11: Reporte Detallado
        self.detailed_report = QTextEdit()
        self.detailed_report.setReadOnly(True)
        self.tabs.addTab(self.detailed_report, "📄 Reporte Detallado")
        
        main_layout.addWidget(self.tabs)
        central_widget.setLayout(main_layout)
    
    def start_analysis(self):
        """Inicia el análisis forense"""
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.analyzer = ForensicAnalyzer()
        self.analyzer.progress.connect(self.update_progress)
        self.analyzer.finished.connect(self.display_results)
        self.analyzer.start()
    
    def update_progress(self, message):
        """Actualiza el mensaje de progreso"""
        self.progress_label.setText(f"Estado: {message}")
    
    def display_results(self, results):
        """Muestra los resultados del análisis"""
        self.analysis_results = results
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        
        # Mostrar resumen
        self._display_summary()
        
        # Mostrar puertos
        self._display_ports()
        
        # Mostrar procesos
        self._display_processes()
        
        # Mostrar conexiones de red
        self._display_network()
        
        # Mostrar actividades sospechosas
        self._display_suspicious()
        
        # Mostrar malware
        self._display_malware()
        
        # Mostrar riesgos de exfiltración
        self._display_exfiltration()
        
        # Mostrar hashes
        self._display_hashes()
        
        # Mostrar registro
        self._display_registry()
        
        # Mostrar DNS
        self._display_dns()
        
        # Mostrar reporte detallado
        self._display_detailed_report()
        
        self.progress_label.setText("✅ Análisis completado exitosamente")
    
    def _display_summary(self):
        """Muestra el resumen ejecutivo"""
        summary_text = f"""
╔════════════════════════════════════════════════════════════╗
║         RESUMEN EJECUTIVO - ANÁLISIS FORENSE DIGITAL       ║
╚════════════════════════════════════════════════════════════╝

📅 Fecha/Hora del Análisis: {self.analysis_results['timestamp']}

📊 ESTADÍSTICAS GENERALES:
─────────────────────────────────────────────────────────────
✓ Puertos Abiertos: {len(self.analysis_results['ports'])}
✓ Procesos Analizados: {len(self.analysis_results['processes'])}
✓ Conexiones de Red Activas: {len(self.analysis_results['network_connections'])}
✓ Actividades Sospechosas: {len(self.analysis_results['suspicious_activities'])}
✓ Indicadores de Malware: {len(self.analysis_results['malware_indicators'])}
✓ Riesgos de Exfiltración: {len(self.analysis_results['exfiltration_risks'])}

🚨 HALLAZGOS CRÍTICOS:
─────────────────────────────────────────────────────────────"""
        
        if self.analysis_results['malware_indicators']:
            summary_text += f"\n⚠️  MALWARE DETECTADO: {len(self.analysis_results['malware_indicators'])} indicador(es)\n"
            for mal in self.analysis_results['malware_indicators'][:3]:
                summary_text += f"   • {mal['malware_family']}: {mal['target']}\n"
        
        if self.analysis_results['exfiltration_risks']:
            summary_text += f"\n⚠️  RIESGOS DE EXFILTRACIÓN: {len(self.analysis_results['exfiltration_risks'])} riesgo(s)\n"
            for risk in self.analysis_results['exfiltration_risks'][:3]:
                summary_text += f"   • {risk['type']}: {risk['target']}\n"
        
        if not self.analysis_results['malware_indicators'] and not self.analysis_results['exfiltration_risks']:
            summary_text += "\n✅ No se detectaron indicadores críticos de malware o exfiltración\n"
        
        summary_text += "\n\n📌 RECOMENDACIONES:\n─────────────────────────────────────────────────────────────\n"
        summary_text += "1. Revisar los procesos marcados como sospechosos\n"
        summary_text += "2. Analizar las conexiones de red a IP externas\n"
        summary_text += "3. Verificar la integridad de archivos críticos del sistema\n"
        summary_text += "4. Monitorear las queries DNS sospechosas\n"
        summary_text += "5. Considerar ejecutar escaneo antimalware adicional\n"
        
        self.summary_tab.setText(summary_text)
    
    def _display_ports(self):
        """Muestra la tabla de puertos"""
        self.ports_table.setRowCount(0)
        
        for port_list in self.analysis_results['ports']:
            for port_info in port_list:
                row = self.ports_table.rowCount()
                self.ports_table.insertRow(row)
                
                # Puerto
                item = QTableWidgetItem(str(port_info['port']))
                self.ports_table.setItem(row, 0, item)
                
                # Servicio
                item = QTableWidgetItem(port_info['service'])
                self.ports_table.setItem(row, 1, item)
                
                # Estado
                item = QTableWidgetItem(port_info['state'])
                self.ports_table.setItem(row, 2, item)
                
                # Sospechoso
                suspicious_text = "⚠️ SÍ" if port_info['suspicious'] else "✓ No"
                item = QTableWidgetItem(suspicious_text)
                if port_info['suspicious']:
                    item.setBackground(QColor(255, 200, 200))
                self.ports_table.setItem(row, 3, item)
                
                # PID
                item = QTableWidgetItem(str(port_info['pid']))
                self.ports_table.setItem(row, 4, item)
        
        self.ports_table.resizeColumnsToContents()
    
    def _display_processes(self):
        """Muestra la tabla de procesos"""
        self.processes_table.setRowCount(0)
        
        for proc in self.analysis_results['processes']:
            row = self.processes_table.rowCount()
            self.processes_table.insertRow(row)
            
            # PID
            item = QTableWidgetItem(str(proc['pid']))
            self.processes_table.setItem(row, 0, item)
            
            # Nombre
            item = QTableWidgetItem(proc['name'])
            self.processes_table.setItem(row, 1, item)
            
            # Ruta
            item = QTableWidgetItem(proc['exe'] if proc['exe'] != 'N/A' else 'Sistema')
            self.processes_table.setItem(row, 2, item)
            
            # Sospechoso
            suspicious_text = "⚠️ SÍ" if proc['suspicious'] else "✓ No"
            item = QTableWidgetItem(suspicious_text)
            if proc['suspicious']:
                item.setBackground(QColor(255, 200, 200))
            self.processes_table.setItem(row, 3, item)
            
            # Razón
            reason_text = ', '.join(proc['reasons']) if proc['reasons'] else 'N/A'
            item = QTableWidgetItem(reason_text)
            self.processes_table.setItem(row, 4, item)
            
            # Creación
            item = QTableWidgetItem(proc['create_time'][:19])
            self.processes_table.setItem(row, 5, item)
        
        self.processes_table.resizeColumnsToContents()
    
    def _display_network(self):
        """Muestra la tabla de conexiones de red"""
        self.network_table.setRowCount(0)
        
        for conn in self.analysis_results['network_connections']:
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)
            
            # Dirección local
            item = QTableWidgetItem(conn['local_addr'])
            self.network_table.setItem(row, 0, item)
            
            # Dirección remota
            item = QTableWidgetItem(conn['remote_addr'])
            if conn.get('suspicious'):
                item.setBackground(QColor(255, 200, 200))
            self.network_table.setItem(row, 1, item)
            
            # Estado
            item = QTableWidgetItem(conn['status'])
            self.network_table.setItem(row, 2, item)
            
            # Proceso
            item = QTableWidgetItem(conn['process'])
            self.network_table.setItem(row, 3, item)
            
            # PID
            item = QTableWidgetItem(str(conn['pid']))
            self.network_table.setItem(row, 4, item)
        
        self.network_table.resizeColumnsToContents()
    
    def _display_suspicious(self):
        """Muestra la tabla de actividades sospechosas"""
        self.suspicious_table.setRowCount(0)
        
        for activity in self.analysis_results['suspicious_activities']:
            row = self.suspicious_table.rowCount()
            self.suspicious_table.insertRow(row)
            
            # Tipo
            item = QTableWidgetItem(activity['type'])
            self.suspicious_table.setItem(row, 0, item)
            
            # Objetivo
            item = QTableWidgetItem(activity['target'])
            item.setBackground(QColor(255, 200, 200))
            self.suspicious_table.setItem(row, 1, item)
            
            # Severidad
            color = QColor(255, 100, 100) if activity['severity'] == 'HIGH' else QColor(255, 200, 100)
            item = QTableWidgetItem(activity['severity'])
            item.setBackground(color)
            self.suspicious_table.setItem(row, 2, item)
            
            # Detalles
            details = ', '.join(activity['details']) if isinstance(activity['details'], list) else str(activity['details'])
            item = QTableWidgetItem(details[:80])
            self.suspicious_table.setItem(row, 3, item)
        
        self.suspicious_table.resizeColumnsToContents()
    
    def _display_malware(self):
        """Muestra la tabla de indicadores de malware"""
        self.malware_table.setRowCount(0)
        
        for indicator in self.analysis_results['malware_indicators']:
            row = self.malware_table.rowCount()
            self.malware_table.insertRow(row)
            
            # Tipo
            item = QTableWidgetItem(indicator['type'])
            item.setBackground(QColor(255, 100, 100))
            self.malware_table.setItem(row, 0, item)
            
            # Familia
            item = QTableWidgetItem(indicator.get('malware_family', 'Unknown'))
            item.setBackground(QColor(255, 100, 100))
            self.malware_table.setItem(row, 1, item)
            
            # Objetivo
            item = QTableWidgetItem(indicator['target'])
            item.setBackground(QColor(255, 100, 100))
            self.malware_table.setItem(row, 2, item)
            
            # Severidad
            item = QTableWidgetItem(indicator['severity'])
            item.setBackground(QColor(255, 100, 100))
            self.malware_table.setItem(row, 3, item)
            
            # PID
            item = QTableWidgetItem(str(indicator.get('pid', 'N/A')))
            self.malware_table.setItem(row, 4, item)
        
        self.malware_table.resizeColumnsToContents()
    
    def _display_exfiltration(self):
        """Muestra la tabla de riesgos de exfiltración"""
        self.exfil_table.setRowCount(0)
        
        for risk in self.analysis_results['exfiltration_risks']:
            row = self.exfil_table.rowCount()
            self.exfil_table.insertRow(row)
            
            # Tipo
            item = QTableWidgetItem(risk['type'])
            item.setBackground(QColor(255, 150, 100))
            self.exfil_table.setItem(row, 0, item)
            
            # Objetivo
            item = QTableWidgetItem(risk['target'])
            item.setBackground(QColor(255, 150, 100))
            self.exfil_table.setItem(row, 1, item)
            
            # Nivel de riesgo
            item = QTableWidgetItem(risk['risk_level'])
            item.setBackground(QColor(255, 150, 100))
            self.exfil_table.setItem(row, 2, item)
            
            # Detalles
            item = QTableWidgetItem(risk.get('details', 'N/A')[:80])
            self.exfil_table.setItem(row, 3, item)
        
        self.exfil_table.resizeColumnsToContents()
    
    def _display_hashes(self):
        """Muestra la tabla de hashes de archivos"""
        self.hashes_table.setRowCount(0)
        
        for file_hash in self.analysis_results['file_hashes']:
            row = self.hashes_table.rowCount()
            self.hashes_table.insertRow(row)
            
            # Ruta
            item = QTableWidgetItem(file_hash['path'])
            self.hashes_table.setItem(row, 0, item)
            
            # MD5
            item = QTableWidgetItem(file_hash['md5'])
            self.hashes_table.setItem(row, 1, item)
            
            # SHA256
            item = QTableWidgetItem(file_hash['sha256'])
            self.hashes_table.setItem(row, 2, item)
        
        self.hashes_table.resizeColumnsToContents()
    
    def _display_registry(self):
        """Muestra la tabla del registro de Windows"""
        self.registry_table.setRowCount(0)
        
        for entry in self.analysis_results['registry_scan']:
            row = self.registry_table.rowCount()
            self.registry_table.insertRow(row)
            
            # Clave
            item = QTableWidgetItem(entry['key'])
            self.registry_table.setItem(row, 0, item)
            
            # Entrada
            item = QTableWidgetItem(entry['entry'][:100])
            self.registry_table.setItem(row, 1, item)
        
        self.registry_table.resizeColumnsToContents()
    
    def _display_dns(self):
        """Muestra la tabla de queries DNS"""
        self.dns_table.setRowCount(0)
        
        for dns_query in self.analysis_results['dns_queries']:
            row = self.dns_table.rowCount()
            self.dns_table.insertRow(row)
            
            # Dominio
            item = QTableWidgetItem(dns_query['query'])
            self.dns_table.setItem(row, 0, item)
            
            # Tipo
            item = QTableWidgetItem('Consulta DNS')
            self.dns_table.setItem(row, 1, item)
        
        self.dns_table.resizeColumnsToContents()
    
    def _display_detailed_report(self):
        """Muestra el reporte detallado completo"""
        report = f"""
╔════════════════════════════════════════════════════════════╗
║            REPORTE FORENSE DIGITAL DETALLADO               ║
╚════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════
📋 INFORMACIÓN GENERAL
═══════════════════════════════════════════════════════════
Fecha/Hora: {self.analysis_results['timestamp']}
Cantidad de procesos analizados: {len(self.analysis_results['processes'])}
Conexiones de red activas: {len(self.analysis_results['network_connections'])}

═══════════════════════════════════════════════════════════
🚨 INDICADORES DE COMPROMISO (IOCs)
═══════════════════════════════════════════════════════════
Total de indicadores detectados: {len(self.analysis_results['malware_indicators'])}

"""
        
        if self.analysis_results['malware_indicators']:
            for mal in self.analysis_results['malware_indicators']:
                report += f"\n[CRÍTICO] {mal['type']}\n"
                report += f"  Familia: {mal.get('malware_family', 'Unknown')}\n"
                report += f"  Objetivo: {mal['target']}\n"
                report += f"  PID: {mal.get('pid', 'N/A')}\n"
                report += f"  Severidad: {mal['severity']}\n"
        else:
            report += "\n✅ No se detectaron indicadores de malware conocidos\n"
        
        report += f"\n\n═══════════════════════════════════════════════════════════\n"
        report += f"📤 RIESGOS DE EXFILTRACIÓN DE DATOS\n"
        report += f"═══════════════════════════════════════════════════════════\n"
        report += f"Total de riesgos detectados: {len(self.analysis_results['exfiltration_risks'])}\n"
        
        if self.analysis_results['exfiltration_risks']:
            for risk in self.analysis_results['exfiltration_risks']:
                report += f"\n[{risk['risk_level']}] {risk['type']}\n"
                report += f"  Destino: {risk['target']}\n"
                report += f"  Proceso: {risk.get('process', 'N/A')}\n"
                report += f"  Detalles: {risk.get('details', 'N/A')}\n"
        else:
            report += "\n✅ No se detectaron riesgos de exfiltración\n"
        
        report += f"\n\n═══════════════════════════════════════════════════════════\n"
        report += f"⚠️  ACTIVIDADES SOSPECHOSAS\n"
        report += f"═══════════════════════════════════════════════════════════\n"
        report += f"Total de actividades sospechosas: {len(self.analysis_results['suspicious_activities'])}\n"
        
        for activity in self.analysis_results['suspicious_activities'][:10]:
            report += f"\n[{activity['severity']}] {activity['type']}\n"
            report += f"  Objetivo: {activity['target']}\n"
            if isinstance(activity['details'], list):
                for detail in activity['details']:
                    report += f"  • {detail}\n"
            else:
                report += f"  Detalles: {activity['details']}\n"
        
        report += f"\n\n═���═════════════════════════════════════════════════════════\n"
        report += f"🔐 INTEGRIDAD DE ARCHIVOS CRÍTICOS\n"
        report += f"═══════════════════════════════════════════════════════════\n"
        
        for file_hash in self.analysis_results['file_hashes']:
            report += f"\n{file_hash['path']}\n"
            report += f"  MD5:    {file_hash['md5']}\n"
            report += f"  SHA256: {file_hash['sha256']}\n"
        
        self.detailed_report.setText(report)
    
    def export_report(self):
        """Exporta el reporte en JSON"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Advertencia", "No hay resultados para exportar")
            return
        
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar Reporte JSON",
            f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)"
        )
        
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(self.analysis_results, f, indent=2, ensure_ascii=False)
                QMessageBox.information(self, "Éxito", f"Reporte exportado a:\n{filepath}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error al exportar: {str(e)}")
    
    def clear_results(self):
        """Limpia los resultados"""
        self.analysis_results = None
        self.summary_tab.clear()
        self.ports_table.setRowCount(0)
        self.processes_table.setRowCount(0)
        self.network_table.setRowCount(0)
        self.suspicious_table.setRowCount(0)
        self.malware_table.setRowCount(0)
        self.exfil_table.setRowCount(0)
        self.hashes_table.setRowCount(0)
        self.registry_table.setRowCount(0)
        self.dns_table.setRowCount(0)
        self.detailed_report.clear()
        self.export_btn.setEnabled(False)
        self.progress_label.setText("Estado: Listo")
    
    def _get_stylesheet(self):
        """Retorna el CSS personalizado"""
        return """
        QMainWindow {
            background-color: #1e1e1e;
            color: #ffffff;
        }
        QTabWidget::pane {
            border: 1px solid #3d3d3d;
        }
        QTabBar::tab {
            background-color: #2d2d2d;
            color: #ffffff;
            padding: 8px 20px;
            border: 1px solid #3d3d3d;
        }
        QTabBar::tab:selected {
            background-color: #3498db;
            color: #ffffff;
        }
        QTableWidget {
            background-color: #2d2d2d;
            color: #ffffff;
            gridline-color: #3d3d3d;
            border: 1px solid #3d3d3d;
        }
        QTableWidget::item {
            padding: 5px;
        }
        QHeaderView::section {
            background-color: #3d3d3d;
            color: #ffffff;
            padding: 5px;
            border: none;
            font-weight: bold;
        }
        QTextEdit {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #3d3d3d;
            font-family: Courier New;
            font-size: 10px;
        }
        QPushButton {
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }
        QPushButton:hover {
            opacity: 0.8;
        }
        QProgressBar {
            background-color: #3d3d3d;
            color: #ffffff;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            height: 20px;
        }
        QProgressBar::chunk {
            background-color: #2ecc71;
        }
        QLabel {
            color: #ffffff;
        }
        QComboBox {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #3d3d3d;
            padding: 5px;
        }
        """


def main():
    app = QApplication(sys.argv)
    window = SecurityAnalyzerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()