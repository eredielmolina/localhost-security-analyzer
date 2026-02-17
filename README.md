# 🛡️ Localhost Security Forensic Analyzer

Herramienta profesional de análisis forense digital para Windows, diseñada para detectar malware, actividades sospechosas y riesgos de exfiltración de datos en localhost.

## 🎯 Características Principales

### ✅ Análisis Completo
- **Puertos Abiertos**: Detecta todos los puertos escuchando con servicios asociados
- **Procesos**: Análisis detallado de procesos en ejecución
- **Conexiones de Red**: Monitoreo de todas las conexiones activas (ESTABLISHED, LISTEN)
- **Registro de Windows**: Escaneo de claves de autoarranque y puntos de persistencia
- **Queries DNS**: Análisis del caché DNS para detectar comunicaciones sospechosas
- **Integridad de Archivos**: Hashing (MD5/SHA256) de archivos críticos del sistema

### 🚨 Detección de Amenazas
- **Malware Detection**: Busca de firmas y patrones de malware conocido
  - WannaCry, Emotet, TrickBot, Mirai, Ransomware, Trojans, Keyloggers
- **Indicadores de Compromiso (IOCs)**: Detecta comportamientos típicos de malware
- **Análisis Criminológico**: Evaluación forense de actividades sospechosas
- **Detección de Ransomware**: Busca de patrones de cifrado y eliminación

### 📤 Análisis de Exfiltración
- **Conexiones Externas**: Identifica comunicaciones a servidores C2 (Command & Control)
- **Puertos de Exfiltración**: Detecta conexiones a puertos comúnmente usados para exfiltración
- **Acceso a Datos Sensibles**: Monitorea acceso a archivos críticos
- **Análisis de Procesos Maliciosos**: Detecta procesos comunicándose con exterior

### 📊 Reportes y Exportación
- **Resumen Ejecutivo**: Análisis de alto nivel con recomendaciones
- **Reportes Detallados**: Información forense completa
- **Exportación JSON**: Guarda todos los datos para análisis posterior
- **Interfaz GUI**: Visualización profesional en tiempo real

## 🚀 Instalación

### Requisitos
- Windows 10/11
- Python 3.8+
- Permisos de Administrador (recomendado)

### Pasos de Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/tu-usuario/localhost-security-analyzer.git
cd localhost-security-analyzer