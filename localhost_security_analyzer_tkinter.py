import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import psutil
import socket
import json
import threading
import hashlib
import os
from datetime import datetime
from collections import defaultdict
import re

class ForensicAnalyzer:
    """Analizador forense digital avanzado"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'ports': [],
            'processes': [],
            'network_connections': [],
            'suspicious_activities': [],
            'file_hashes': [],
            'registry_scan': [],
            'malware_indicators': [],
            'exfiltration_risks': [],
        }
        self.malware_signatures = self._load_malware_signatures()
        self.suspicious_ports = {445, 139, 135, 3389, 4444, 5555, 6666}
    
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
    
    def analyze_ports(self):
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
            return True
        except Exception as e:
            print(f"Error analizando puertos: {str(e)}")
            return False
    
    def analyze_processes(self):
        """Analiza procesos en ejecución"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cwd']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'cwd', 'create_time'])
                    
                    suspicious = False
                    suspicious_reason = []
                    
                    name_lower = pinfo['name'].lower()
                    suspicious_processes = ['mimikatz', 'psexec', 'nmap', 'wireshark', 'tcpdump']
                    
                    if any(mal in name_lower for mal in suspicious_processes):
                        suspicious = True
                        suspicious_reason.append("Nombre de proceso conocido como malware")
                    
                    process_info = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo.get('exe', 'N/A'),
                        'cmdline': ' '.join(pinfo.get('cmdline', [])) if pinfo.get('cmdline') else 'N/A',
                        'suspicious': suspicious,
                        'reasons': suspicious_reason
                    }
                    
                    self.results['processes'].append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return True
        except Exception as e:
            print(f"Error analizando procesos: {str(e)}")
            return False
    
    def analyze_network_connections(self):
        """Analiza conexiones de red activas"""
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
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
                    }
                    
                    self.results['network_connections'].append(conn_info)
            
            return True
        except Exception as e:
            print(f"Error analizando conexiones: {str(e)}")
            return False
    
    def detect_suspicious_activities(self):
        """Detecta actividades sospechosas"""
        suspicious = []
        
        for proc_info in self.results['processes']:
            if proc_info['suspicious']:
                suspicious.append({
                    'type': 'Proceso Sospechoso',
                    'target': proc_info['name'],
                    'severity': 'HIGH',
                })
        
        for conn in self.results['network_connections']:
            if 'remote_addr' in conn and ':' in conn['remote_addr']:
                ip = conn['remote_addr'].split(':')[0]
                if not any(ip.startswith(r) for r in ['127.', '192.168.', '10.', '172.']):
                    suspicious.append({
                        'type': 'Conexión Externa',
                        'target': conn['remote_addr'],
                        'severity': 'MEDIUM',
                    })
        
        self.results['suspicious_activities'] = suspicious
        return True
    
    def hash_critical_files(self):
        """Calcula hash de archivos críticos"""
        critical_paths = [
            'C:\\Windows\\System32\\cmd.exe',
            'C:\\Windows\\System32\\powershell.exe',
            'C:\\Windows\\System32\\services.exe',
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
                    })
                except Exception as e:
                    print(f"Error hasheando {path}: {str(e)}")
        
        return True
    
    def _calculate_hash(self, filepath, hash_type='sha256'):
        """Calcula hash de un archivo"""
        hash_obj = hashlib.new(hash_type)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def detect_malware_indicators(self):
        """Detecta indicadores de malware"""
        indicators = []
        
        for proc_info in self.results['processes']:
            proc_name_lower = proc_info['name'].lower()
            for malware_type, signatures in self.malware_signatures.items():
                if any(sig in proc_name_lower for sig in signatures):
                    indicators.append({
                        'type': 'Proceso Malware',
                        'family': malware_type,
                        'target': proc_info['name'],
                        'severity': 'CRITICAL',
                    })
        
        self.results['malware_indicators'] = indicators
        return True
    
    def analyze_exfiltration_risks(self):
        """Analiza riesgos de exfiltración"""
        risks = []
        
        for conn in self.results['network_connections']:
            if 'remote_addr' in conn:
                remote_ip = conn['remote_addr'].split(':')[0]
                try:
                    remote_port = int(conn['remote_addr'].split(':')[1])
                except:
                    remote_port = 0
                
                exfil_ports = {25, 53, 443, 8080, 8443, 1433, 3306, 5432}
                if remote_port in exfil_ports and not any(remote_ip.startswith(r) for r in ['127.', '192.168.', '10.', '172.']):
                    risks.append({
                        'type': 'Exfiltración Potencial',
                        'target': conn['remote_addr'],
                        'process': conn['process'],
                        'risk_level': 'MEDIUM',
                    })
        
        self.results['exfiltration_risks'] = risks
        return True
    
    def export_report(self, filepath):
        """Exporta reporte en JSON"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)


class SecurityAnalyzerGUI:
    """Interfaz gráfica con Tkinter"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Localhost Security Forensic Analyzer")
        self.root.geometry("1200x700")
        self.root.configure(bg='#1e1e1e')
        
        self.analyzer = None
        self.analysis_results = None
        
        self.init_ui()
    
    def init_ui(self):
        """Inicializa la interfaz"""
        # Frame superior
        top_frame = tk.Frame(self.root, bg='#2d2d2d')
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_btn = tk.Button(
            top_frame,
            text="🔍 Iniciar Análisis Forense",
            command=self.start_analysis,
            bg='#2ecc71',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=15,
            pady=10
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = tk.Button(
            top_frame,
            text="📊 Exportar Reporte JSON",
            command=self.export_report,
            bg='#3498db',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=15,
            pady=10,
            state=tk.DISABLED
        )
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = tk.Button(
            top_frame,
            text="🗑️ Limpiar",
            command=self.clear_results,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=15,
            pady=10
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Etiqueta de estado
        self.status_label = tk.Label(
            self.root,
            text="Estado: Listo",
            bg='#1e1e1e',
            fg='#ffffff',
            font=('Arial', 10)
        )
        self.status_label.pack(fill=tk.X, padx=10, pady=5)
        
        # Barra de progreso
        self.progress_bar = ttk.Progressbar(
            self.root,
            mode='indeterminate',
            length=400
        )
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        self.progress_bar.pack_forget()
        
        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Resumen
        self.summary_text = tk.Text(self.notebook, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.summary_text, text="📋 Resumen")
        
        # Tab 2: Puertos
        self.ports_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.ports_text = tk.Text(self.ports_frame, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.ports_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.ports_frame, text="🔌 Puertos")
        
        # Tab 3: Procesos
        self.processes_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.processes_text = tk.Text(self.processes_frame, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.processes_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.processes_frame, text="⚙️ Procesos")
        
        # Tab 4: Conexiones de Red
        self.network_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.network_text = tk.Text(self.network_frame, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.network_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.network_frame, text="🌐 Conexiones")
        
        # Tab 5: Malware
        self.malware_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.malware_text = tk.Text(self.malware_frame, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.malware_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.malware_frame, text="🦠 Malware")
        
        # Tab 6: Exfiltración
        self.exfil_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.exfil_text = tk.Text(self.exfil_frame, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.exfil_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.exfil_frame, text="📤 Exfiltración")
        
        # Tab 7: Actividades Sospechosas
        self.suspicious_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.suspicious_text = tk.Text(self.suspicious_frame, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.suspicious_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.suspicious_frame, text="⚠️ Sospechoso")
        
        # Tab 8: Hashes
        self.hashes_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.hashes_text = tk.Text(self.hashes_frame, height=20, width=80, bg='#2d2d2d', fg='#ffffff')
        self.hashes_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.hashes_frame, text="🔐 Hashes")
    
    def start_analysis(self):
        """Inicia el análisis"""
        self.scan_btn.config(state=tk.DISABLED)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        self.progress_bar.start()
        
        def run():
            try:
                self.status_label.config(text="Estado: Analizando puertos...")
                self.root.update()
                
                analyzer = ForensicAnalyzer()
                
                self.status_label.config(text="Estado: Analizando procesos...")
                self.root.update()
                analyzer.analyze_processes()
                
                self.status_label.config(text="Estado: Analizando conexiones de red...")
                self.root.update()
                analyzer.analyze_network_connections()
                
                self.status_label.config(text="Estado: Analizando puertos...")
                self.root.update()
                analyzer.analyze_ports()
                
                self.status_label.config(text="Estado: Detectando actividades sospechosas...")
                self.root.update()
                analyzer.detect_suspicious_activities()
                
                self.status_label.config(text="Estado: Hasheando archivos críticos...")
                self.root.update()
                analyzer.hash_critical_files()
                
                self.status_label.config(text="Estado: Detectando malware...")
                self.root.update()
                analyzer.detect_malware_indicators()
                
                self.status_label.config(text="Estado: Analizando riesgos de exfiltración...")
                self.root.update()
                analyzer.analyze_exfiltration_risks()
                
                self.analysis_results = analyzer.results
                self.display_results()
                
                self.status_label.config(text="✅ Análisis completado")
                self.export_btn.config(state=tk.NORMAL)
                
            except Exception as e:
                messagebox.showerror("Error", f"Error durante el análisis: {str(e)}")
                self.status_label.config(text=f"❌ Error: {str(e)}")
            finally:
                self.progress_bar.stop()
                self.progress_bar.pack_forget()
                self.scan_btn.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
    
    def display_results(self):
        """Muestra los resultados"""
        # Resumen
        summary = f"""
╔════════════════════════════════════════════════════════════╗
║         RESUMEN EJECUTIVO - ANÁLISIS FORENSE DIGITAL       ║
╚════════════════════════════════════════════════════════════╝

📅 Fecha/Hora: {self.analysis_results['timestamp']}

📊 ESTADÍSTICAS:
─────────────────────────────────────────────────────────────
✓ Puertos Abiertos: {len(self.analysis_results['ports'])}
✓ Procesos: {len(self.analysis_results['processes'])}
✓ Conexiones Red: {len(self.analysis_results['network_connections'])}
✓ Actividades Sospechosas: {len(self.analysis_results['suspicious_activities'])}
✓ Indicadores de Malware: {len(self.analysis_results['malware_indicators'])}
✓ Riesgos de Exfiltración: {len(self.analysis_results['exfiltration_risks'])}

🚨 HALLAZGOS CRÍTICOS:
─────────────────────────────────────────────────────────────"""
        
        if self.analysis_results['malware_indicators']:
            summary += f"\n⚠️ MALWARE DETECTADO: {len(self.analysis_results['malware_indicators'])}\n"
            for mal in self.analysis_results['malware_indicators'][:3]:
                summary += f"   • {mal['family']}: {mal['target']}\n"
        else:
            summary += "\n✅ No se detectó malware\n"
        
        if self.analysis_results['exfiltration_risks']:
            summary += f"\n⚠️ RIESGOS DE EXFILTRACIÓN: {len(self.analysis_results['exfiltration_risks'])}\n"
            for risk in self.analysis_results['exfiltration_risks'][:3]:
                summary += f"   • {risk['type']}: {risk['target']}\n"
        
        self.summary_text.insert(tk.END, summary)
        
        # Puertos
        ports_text = "PUERTOS ABIERTOS\n" + "="*60 + "\n\n"
        for port_list in self.analysis_results['ports']:
            for port in port_list:
                suspicious = "⚠️" if port['suspicious'] else "✓"
                ports_text += f"{suspicious} Puerto {port['port']}: {port['service']} ({port['state']})\n"
        self.ports_text.insert(tk.END, ports_text)
        
        # Procesos
        procs_text = "PROCESOS EN EJECUCIÓN\n" + "="*60 + "\n\n"
        for proc in self.analysis_results['processes'][:20]:
            suspicious = "⚠️ SOSPECHOSO" if proc['suspicious'] else "✓"
            procs_text += f"[{suspicious}] PID {proc['pid']}: {proc['name']}\n"
            if proc['reasons']:
                for reason in proc['reasons']:
                    procs_text += f"    └─ {reason}\n"
            procs_text += "\n"
        self.processes_text.insert(tk.END, procs_text)
        
        # Conexiones de Red
        net_text = "CONEXIONES DE RED ACTIVAS\n" + "="*60 + "\n\n"
        for conn in self.analysis_results['network_connections'][:20]:
            net_text += f"Local: {conn['local_addr']}\n"
            net_text += f"Remota: {conn['remote_addr']}\n"
            net_text += f"Proceso: {conn['process']} (PID: {conn['pid']})\n"
            net_text += f"Estado: {conn['status']}\n"
            net_text += "─" * 60 + "\n"
        self.network_text.insert(tk.END, net_text)
        
        # Malware
        mal_text = "INDICADORES DE MALWARE DETECTADOS\n" + "="*60 + "\n\n"
        if self.analysis_results['malware_indicators']:
            for mal in self.analysis_results['malware_indicators']:
                mal_text += f"🦠 {mal['family'].upper()}\n"
                mal_text += f"   Tipo: {mal['type']}\n"
                mal_text += f"   Objetivo: {mal['target']}\n"
                mal_text += f"   Severidad: {mal['severity']}\n\n"
        else:
            mal_text += "✅ No se detectó malware\n"
        self.malware_text.insert(tk.END, mal_text)
        
        # Exfiltración
        exfil_text = "RIESGOS DE EXFILTRACIÓN\n" + "="*60 + "\n\n"
        if self.analysis_results['exfiltration_risks']:
            for risk in self.analysis_results['exfiltration_risks']:
                exfil_text += f"⚠️ {risk['type']}\n"
                exfil_text += f"   Destino: {risk['target']}\n"
                exfil_text += f"   Proceso: {risk['process']}\n"
                exfil_text += f"   Nivel: {risk['risk_level']}\n\n"
        else:
            exfil_text += "✅ No se detectaron riesgos\n"
        self.exfil_text.insert(tk.END, exfil_text)
        
        # Actividades Sospechosas
        susp_text = "ACTIVIDADES SOSPECHOSAS\n" + "="*60 + "\n\n"
        if self.analysis_results['suspicious_activities']:
            for activity in self.analysis_results['suspicious_activities'][:15]:
                susp_text += f"[{activity['severity']}] {activity['type']}\n"
                susp_text += f"    Objetivo: {activity['target']}\n\n"
        else:
            susp_text += "✅ No se detectaron actividades sospechosas\n"
        self.suspicious_text.insert(tk.END, susp_text)
        
        # Hashes
        hash_text = "HASHES DE ARCHIVOS CRÍTICOS\n" + "="*60 + "\n\n"
        for file_hash in self.analysis_results['file_hashes']:
            hash_text += f"{file_hash['path']}\n"
            hash_text += f"  MD5:    {file_hash['md5']}\n"
            hash_text += f"  SHA256: {file_hash['sha256']}\n\n"
        self.hashes_text.insert(tk.END, hash_text)
    
    def export_report(self):
        """Exporta el reporte"""
        if not self.analysis_results:
            messagebox.showwarning("Advertencia", "No hay resultados para exportar")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filepath:
            try:
                analyzer = ForensicAnalyzer()
                analyzer.results = self.analysis_results
                analyzer.export_report(filepath)
                messagebox.showinfo("Éxito", f"Reporte exportado a:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al exportar: {str(e)}")
    
    def clear_results(self):
        """Limpia los resultados"""
        self.summary_text.delete(1.0, tk.END)
        self.ports_text.delete(1.0, tk.END)
        self.processes_text.delete(1.0, tk.END)
        self.network_text.delete(1.0, tk.END)
        self.malware_text.delete(1.0, tk.END)
        self.exfil_text.delete(1.0, tk.END)
        self.suspicious_text.delete(1.0, tk.END)
        self.hashes_text.delete(1.0, tk.END)
        self.analysis_results = None
        self.export_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Estado: Listo")


if __name__ == '__main__':
    root = tk.Tk()
    gui = SecurityAnalyzerGUI(root)
    root.mainloop()