# 🛡️ Localhost Security Forensic Analyzer

Herramienta profesional de análisis forense digital para Windows, diseñada para detectar malware, actividades sospechosas y riesgos de exfiltración de datos en localhost.

## 🎯 Características Principales

### ✅ Análisis Completo
- **Puertos Abiertos**: Detecta todos los puertos escuchando con servicios asociados
- **Procesos**: Análisis detallado de procesos en ejecución
- **Conexiones de Red**: Monitoreo de todas las conexiones activas (ESTABLISHED, LISTEN)
- **Registro de Windows**: Escaneo de claves de autoarranque y puntos de persistencia
- **Consultas DNS**: Análisis del caché DNS para detectar comunicaciones sospechosas
- **Integridad de Archivos**: Hashing (MD5/SHA256) de archivos críticos del sistema

### 🚨 Detección de Amenazas
- **Detección de Malware**: Búsqueda de firmas y patrones de malware conocido
  - WannaCry, Emotet, TrickBot, Mirai, Ransomware, Troyanos, Keyloggers
- **Indicadores de Compromiso (IOCs)**: Detecta comportamientos típicos de malware
- **Análisis Criminológico**: Evaluación forense de actividades sospechosas
- **Detección de Ransomware**: Búsqueda de patrones de cifrado y eliminación

### 📤 Análisis de Exfiltración
- **Conexiones Externas**: Identifica comunicaciones a servidores C2 (Command & Control)
- **Puertos de Exfiltración**: Detecta conexiones a puertos comúnmente usados para exfiltración
- **Acceso a Datos Sensibles**: Monitorea acceso a archivos críticos
- **Análisis de Procesos Maliciosos**: Detecta procesos comunicándose con el exterior

### 🔬 Análisis Forense de Aplicaciones
- **Examen Profundo**: Inspección forense detallada de cada aplicación en ejecución
- **Módulos Cargados**: Identifica todas las librerías y dependencias de cada proceso
- **Archivos Abiertos**: Lista los archivos que cada aplicación tiene abiertos
- **Conexiones por Proceso**: Analiza las conexiones de red individuales de cada aplicación
- **Información del Ejecutable**: Tamaño, hash SHA256, fechas de creación y modificación
- **Procesos Hijos**: Detecta la jerarquía de procesos padre-hijo
- **Uso de Recursos**: Memoria RSS/VMS, CPU y número de hilos por aplicación
- **Evaluación de Riesgo**: Puntuación de riesgo (0-100) con clasificación automática (CRITICAL/HIGH/MEDIUM/LOW)

### 📊 Reportes y Exportación
- **Resumen Ejecutivo**: Análisis de alto nivel con recomendaciones
- **Reportes Detallados**: Información forense completa
- **Exportación JSON**: Guarda todos los datos para análisis posterior
- **Interfaz GUI**: Visualización profesional en tiempo real

## 🚀 Instalación

### Requisitos Previos
- **Sistema Operativo**: Windows 10/11 (algunas funciones como el registro de Windows y caché DNS son específicas de Windows, pero el análisis de procesos, puertos y red funciona también en Linux/macOS)
- **Python**: 3.8 o superior
- **Permisos de Administrador**: Recomendado para acceso completo a todos los procesos y conexiones

### Paso 1: Clonar el repositorio

```bash
git clone https://github.com/eredielmolina/localhost-security-analyzer.git
cd localhost-security-analyzer
```

### Paso 2: Crear un entorno virtual (recomendado)

```bash
python -m venv venv
```

Activar el entorno virtual:

- **Windows (CMD)**:
  ```bash
  venv\Scripts\activate
  ```
- **Windows (PowerShell)**:
  ```bash
  venv\Scripts\Activate.ps1
  ```
- **Linux/macOS**:
  ```bash
  source venv/bin/activate
  ```

### Paso 3: Instalar las dependencias

```bash
pip install -r requirements.txt
```

### Paso 4: Ejecutar la aplicación

```bash
python localhost_security_analyzer.py
```

> **Nota**: Para obtener resultados más completos, se recomienda ejecutar con permisos de administrador:
> - **Windows**: Abrir la terminal como Administrador antes de ejecutar el script.
> - **Linux/macOS**: `sudo python localhost_security_analyzer.py`

## 🧪 Ejecutar las Pruebas

El proyecto incluye un conjunto de pruebas unitarias para verificar el correcto funcionamiento del análisis forense de aplicaciones.

```bash
python -m unittest test_forensic_analyzer -v
```

Resultado esperado: 12 tests pasando correctamente, incluyendo:
- Inicialización del analizador
- Análisis forense básico
- Evaluación de riesgo (bajo, alto, por directorio temporal, por hilos)
- Cálculo de memoria
- Deduplicación por ejecutable
- Manejo de errores de acceso denegado
- Detección de directorio temporal en Linux (/tmp)
- Manejo de errores de lectura de archivos
- Configuración del logger

## 📁 Estructura del Proyecto

```
localhost-security-analyzer/
├── localhost_security_analyzer.py   # Código principal (analizador + GUI)
├── test_forensic_analyzer.py        # Pruebas unitarias
├── config.json                      # Configuración del análisis
├── requirements.txt                 # Dependencias del proyecto
├── SECURITY.md                      # Política de seguridad
├── .gitignore                       # Archivos ignorados por git
└── README.md                        # Este archivo
```

## ⚙️ Configuración

El archivo `config.json` permite personalizar el comportamiento del análisis:

```json
{
  "scan_settings": {
    "deep_scan": true,
    "check_system_files": true,
    "check_registry": true,
    "check_dns_cache": true,
    "timeout_seconds": 30
  },
  "forensic_analysis": {
    "enabled": true,
    "analyze_loaded_modules": true,
    "analyze_open_files": true,
    "analyze_network_per_process": true,
    "analyze_child_processes": true,
    "hash_executables": true,
    "max_modules_per_process": 50,
    "max_open_files_per_process": 30,
    "max_connections_per_process": 20
  }
}
```

## 🖥️ Uso de la Interfaz Gráfica

Al ejecutar la aplicación se abrirá una ventana con las siguientes funciones:

1. **🔍 Iniciar Análisis Forense**: Pulsar este botón para comenzar un escaneo completo del sistema.
2. **📊 Exportar Reporte JSON**: Una vez completado el análisis, permite guardar todos los resultados en formato JSON.
3. **🗑️ Limpiar Resultados**: Borra los resultados del análisis actual.

### Pestañas de Resultados

| Pestaña | Descripción |
|---------|-------------|
| 📋 Resumen Ejecutivo | Visión general con estadísticas y hallazgos críticos |
| 🔌 Puertos | Puertos abiertos detectados con servicios asociados |
| ⚙️ Procesos | Lista de procesos en ejecución con detección de sospechosos |
| 🌐 Conexiones Red | Conexiones de red activas (ESTABLISHED/LISTEN) |
| ⚠️ Actividades Sospechosas | Procesos y conexiones marcados como sospechosos |
| 🦠 Malware Detectado | Indicadores de malware encontrados |
| 📤 Riesgos de Exfiltración | Posibles riesgos de fuga de datos |
| 🔐 Hashes de Archivos | Hashes MD5/SHA256 de archivos críticos del sistema |
| 📝 Registro de Windows | Entradas de autoarranque del registro |
| 🌐 DNS | Consultas DNS en caché |
| 🔬 Análisis Forense Apps | Análisis profundo de cada aplicación con puntuación de riesgo |
| 📄 Reporte Detallado | Informe forense completo |

## 🔬 Análisis Forense de Aplicaciones

Esta funcionalidad realiza una inspección profunda de cada proceso en ejecución:

- **Deduplicación**: Analiza cada ejecutable una sola vez, evitando duplicados
- **Módulos cargados**: Lista las librerías y dependencias de cada proceso (hasta 50)
- **Archivos abiertos**: Muestra los archivos que cada proceso tiene abiertos (hasta 30)
- **Conexiones de red**: Detalla las conexiones individuales de cada proceso (hasta 20)
- **Información del ejecutable**: Tamaño, hash SHA256, fechas de creación y modificación
- **Procesos hijos**: Detecta la jerarquía padre-hijo
- **Uso de recursos**: Memoria RSS/VMS, porcentaje de CPU y número de hilos

### Sistema de Evaluación de Riesgo

Cada aplicación recibe una puntuación de riesgo (0-100) basada en:

| Criterio | Puntuación |
|----------|-----------|
| Nombre asociado a herramientas de hacking | +40 |
| Firma de malware conocida | +50 |
| Ejecutable en directorio temporal | +30 |
| Conexiones externas activas | +15 |
| Número alto de hilos (>100) | +10 |

Clasificación resultante:

| Puntuación | Nivel |
|-----------|-------|
| ≥ 70 | 🔴 CRITICAL |
| ≥ 40 | 🟠 HIGH |
| ≥ 20 | 🟡 MEDIUM |
| < 20 | 🟢 LOW |

## 📜 Licencia

Este proyecto es de código abierto. Consulta el archivo de licencia para más detalles.

## ⚠️ Aviso Legal

Esta herramienta está diseñada exclusivamente para fines educativos y de auditoría de seguridad en sistemas propios. El uso de esta herramienta en sistemas sin autorización es ilegal y va contra los términos de uso. El autor no se hace responsable del uso indebido de esta herramienta.