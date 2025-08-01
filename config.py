"""
 Configuración del Escáner de Vulnerabilidades
============================================

Este archivo contiene todas las configuraciones y constantes
utilizadas en el escáner de vulnerabilidades.
"""

import os

# Información del proyecto
PROJECT_NAME = "Escáner Avanzado de Vulnerabilidades y Exploits"
VERSION = "1.0.0"
AUTHOR = "3stefani"

# Configuración de APIs y URLs
API_CONFIG = {
    'nvd_base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    'circl_base_url': 'https://cve.circl.lu/api/cve',
    'exploitdb_csv_url': 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
    'cvedetails_base_url': 'https://www.cvedetails.com/cve',
    'exploitdb_base_url': 'https://www.exploit-db.com/exploits'
}

# Headers para las peticiones HTTP
HTTP_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Configuración de timeouts y límites
TIMEOUTS = {
    'nvd_request': 15,      # segundos
    'circl_request': 10,    # segundos
    'general_request': 12,  # segundos
    'rate_limit_delay': 0.5 # segundos entre peticiones
}

LIMITS = {
    'max_results_per_search': 20,    # Máximo de CVEs por búsqueda
    'max_concurrent_workers': 2,     # Máximo de hilos concurrentes
    'max_exploits_per_cve': 5,       # Máximo de exploits a mostrar por CVE
    'max_urls_in_table': 3,          # Máximo de URLs a mostrar en tabla
    'max_description_length': 120    # Máximo de caracteres en descripción
}

# Archivos y directorios
FILES = {
    'exploitdb_csv': 'exploitdb_files.csv',
    'logs_dir': 'logs',
    'cache_dir': 'cache'
}

# Configuración de logging
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': os.path.join(FILES['logs_dir'], 'scanner.log')
}

# Dominios confiables para validación de exploits
TRUSTED_DOMAINS = [
    'exploit-db.com',
    'github.com',
    'packetstormsecurity.com',
    'seclists.org',
    'cve.mitre.org',
    'nvd.nist.gov',
    'cvedetails.com',
    'security.gentoo.org',
    'vuldb.com'
]

# Patrones de URLs inválidas
INVALID_URL_PATTERNS = [
    '/search?',
    '/about',
    '/contact',
    '/features',
    '/pricing',
    '/login',
    '/register',
    '/terms',
    '/privacy',
    '/help',
    '/support'
]

# Palabras clave para identificar exploits
EXPLOIT_KEYWORDS = [
    'exploit',
    'poc',
    'proof',
    'vulnerability',
    'security',
    'advisory',
    'patch'
]

# Configuración de colores para CVSS
CVSS_COLORS = {
    'critical': (9.0, 10.0, 'red bold'),      # CVSS 9.0-10.0
    'high': (7.0, 8.9, 'red'),                # CVSS 7.0-8.9
    'medium': (4.0, 6.9, 'yellow'),           # CVSS 4.0-6.9
    'low': (0.1, 3.9, 'green'),               # CVSS 0.1-3.9
    'none': (0.0, 0.0, 'dim')                 # Sin CVSS
}

# Mensajes de la aplicación
MESSAGES = {
    'banner': "🔍 ESCÁNER AVANZADO DE VULNERABILIDADES Y EXPLOITS",
    'downloading_db': "Descargando base de datos de Exploit-DB...",
    'db_downloaded': "✅ Base de datos de Exploit-DB descargada correctamente",
    'db_download_error': "⚠️ No se pudo descargar la base de datos",
    'searching_cves': "Buscando CVEs para '{}' en NVD...",
    'processing_cves': "✅ Encontrados {} CVEs. Procesando...",
    'searching_exploits': "🔥 Buscando exploits disponibles...",
    'analysis_complete': "✅ Análisis completado en {:.1f} segundos",
    'no_vulnerabilities': "❌ No se encontraron vulnerabilidades para este servicio.",
    'interrupted': "⚠️ Análisis interrumpido por el usuario.",
    'unexpected_error': "❌ Error inesperado: {}",
    'goodbye': "✨ ¡Gracias por usar el Escáner de Vulnerabilidades! ✨",
    'stay_safe': "🛡️ Recuerde mantener sus sistemas actualizados y seguros."
}

# Ejemplos de búsqueda
SEARCH_EXAMPLES = [
    "wordpress",
    "apache httpd", 
    "mysql",
    "nginx",
    "php",
    "windows server",
    "linux kernel",
    "openssh",
    "tomcat",
    "jenkins"
]

# Configuración de fuentes de datos
DATA_SOURCES = {
    'nvd': {
        'name': 'NVD (National Vulnerability Database)',
        'enabled': True,
        'priority': 1
    },
    'exploitdb': {
        'name': 'Exploit-DB (Base de datos local)',
        'enabled': True,
        'priority': 2
    },
    'circl': {
        'name': 'CIRCL CVE Search API',
        'enabled': True,
        'priority': 3
    },
    'cvedetails': {
        'name': 'CVEDetails para información detallada',
        'enabled': True,
        'priority': 4
    }
}

# Funciones utilitarias de configuración
def get_api_url(api_name, endpoint=''):
    """Construir URL completa para API"""
    base_url = API_CONFIG.get(f'{api_name}_base_url', '')
    if endpoint:
        return f"{base_url}/{endpoint}".replace('//', '/')
    return base_url

def get_timeout(request_type='general'):
    """Obtener timeout para tipo de petición"""
    return TIMEOUTS.get(f'{request_type}_request', TIMEOUTS['general_request'])

def get_limit(limit_type):
    """Obtener límite específico"""
    return LIMITS.get(limit_type, 0)

def is_trusted_domain(url):
    """Verificar si la URL es de un dominio confiable"""
    return any(domain in url.lower() for domain in TRUSTED_DOMAINS)

def has_invalid_pattern(url):
    """Verificar si la URL tiene patrones inválidos"""
    return any(pattern in url.lower() for pattern in INVALID_URL_PATTERNS)

def get_cvss_color(cvss_score):
    """Obtener color para mostrar CVSS según su valor"""
    for severity, (min_val, max_val, color) in CVSS_COLORS.items():
        if min_val <= cvss_score <= max_val:
            return color
    return CVSS_COLORS['none'][2]

# Configuración de desarrollo/producción
DEBUG = os.getenv('SCANNER_DEBUG', 'False').lower() == 'true'
ENABLE_CACHING = os.getenv('ENABLE_CACHING', 'True').lower() == 'true'
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()