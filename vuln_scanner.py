import requests
import csv
import os
import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor


class VulnScanner:
    """
    Escáner de vulnerabilidades que busca CVEs y exploits disponibles
    utilizando múltiples fuentes de datos confiables.
    """

    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.exploitdb_csv_path = 'exploitdb_files.csv'
        self.setup_exploitdb_database()

    def setup_exploitdb_database(self):
        """Descarga la base de datos de Exploit-DB si no existe"""
        if not os.path.exists(self.exploitdb_csv_path):
            print("📥 Descargando base de datos de Exploit-DB...")
            try:
                # URL directa del CSV de Exploit-DB
                url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
                urllib.request.urlretrieve(url, self.exploitdb_csv_path)
                print("✅ Base de datos de Exploit-DB descargada correctamente")
            except Exception as e:
                print(f"⚠️ No se pudo descargar la base de datos: {e}")
                print("   Continuando sin base de datos local...")

    def search_cves(self, service):
        """Buscar CVEs usando NVD API"""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=20"
        
        try:
            print(f"Buscando CVEs para '{service}' en NVD...")
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code != 200:
                return f"Error HTTP {response.status_code}: No se pudo conectar con NVD"
                
            data_dict = response.json()
            
        except requests.RequestException as e:
            return f"Error de conexión: {str(e)}"
        except json.JSONDecodeError:
            return "Error: Respuesta inválida de NVD"
        
        if 'vulnerabilities' not in data_dict or not data_dict['vulnerabilities']:
            return f"No se encontraron vulnerabilidades para '{service}'"
        
        cves_info = []
        print(f"👻 Encontrados {len(data_dict['vulnerabilities'])} CVEs. Procesando...")

        for vulnerability in data_dict['vulnerabilities']:
            cve_data = vulnerability['cve']
            cve_id = cve_data['id']
            
            # Obtener descripción
            descriptions = cve_data['descriptions']
            description = next((desc['value'] for desc in descriptions if desc['lang'] == 'es'), None)
            if not description:
                description = next((desc['value'] for desc in descriptions if desc['lang'] == 'en'), 'No disponible')
            
            # Obtener CVSS directamente de los datos
            cvss_score = 'No disponible'
            metrics = cve_data.get('metrics', {})
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
            
            # Obtener fecha de publicación
            published_date = cve_data.get('published', 'No disponible')
            
            cve_info = {
                'cve_id': cve_id,
                'description': description,
                'cvss': cvss_score,
                'published': published_date,
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'exploits_available': False,
                'exploit_urls': [],
                'exploit_count': 0
            }
            
            cves_info.append(cve_info)

        # Buscar exploits para cada CVE (con menos concurrencia)
        print("⚡ Buscando exploits disponibles...")
        with ThreadPoolExecutor(max_workers=2) as executor:
            executor.map(self.search_exploits_for_cve, cves_info)

        return cves_info

    def search_exploits_for_cve(self, cve_info):
        """Buscar exploits usando múltiples fuentes confiables"""
        cve_id = cve_info['cve_id']
        print(f"   Buscando exploits para {cve_id}")
        
        all_exploits = []
        
        # 1. Buscar en Exploit-DB local
        exploitdb_results = self.search_exploitdb_by_cve(cve_id)
        all_exploits.extend(exploitdb_results)
        
        # 2. Buscar en CIRCL CVE Search API
        circl_results = self.search_circl_api(cve_id)
        all_exploits.extend(circl_results)
        
        # 3. Buscar en referencias de NVD
        nvd_results = self.search_nvd_references(cve_id)
        all_exploits.extend(nvd_results)
        
        # Filtrar y limpiar resultados
        valid_exploits = []
        seen_urls = set()
        
        for exploit in all_exploits:
            if exploit and exploit not in seen_urls:
                if self.validate_exploit_url(exploit):
                    valid_exploits.append(exploit)
                    seen_urls.add(exploit)
        
        # Actualizar información del CVE
        if valid_exploits:
            cve_info['exploits_available'] = True
            cve_info['exploit_urls'] = valid_exploits[:5]  # Máximo 5
            cve_info['exploit_count'] = len(valid_exploits)
            print(f"   👻 {len(valid_exploits)} exploit(s) encontrado(s) para {cve_id}")
        else:
            print(f"   ❌ No se encontraron exploits para {cve_id}")
        
        time.sleep(0.5)  # Rate limiting

    def search_exploitdb_by_cve(self, cve_id):
        """Buscar en la base de datos local de Exploit-DB"""
        exploits = []
        
        if not os.path.exists(self.exploitdb_csv_path):
            return exploits
        
        try:
            with open(self.exploitdb_csv_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Buscar CVE en las columnas relevantes
                    cve_column = row.get('cve', '') or row.get('CVE', '') or row.get('codes', '')
                    if cve_id.upper() in cve_column.upper():
                        exploit_id = row.get('id', '')
                        if exploit_id:
                            exploit_url = f"https://www.exploit-db.com/exploits/{exploit_id}"
                            exploits.append(exploit_url)
                            
        except Exception as e:
            print(f"     ⚠️ Error leyendo base de datos local: {e}")
        
        return exploits

    def search_circl_api(self, cve_id):
        """Buscar usando CIRCL CVE Search API"""
        exploits = []
        
        try:
            # API de CIRCL para obtener información del CVE
            url = f"https://cve.circl.lu/api/cve/{cve_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Buscar en referencias
                references = data.get('references', [])
                for ref in references:
                    ref_url = ref.lower()
                    # Filtrar URLs que probablemente contengan exploits
                    if any(keyword in ref_url for keyword in ['exploit', 'poc', 'proof', 'github.com']):
                        if ref.startswith('http'):
                            exploits.append(ref)
                
                # Buscar en campo específico de exploits si existe
                if 'exploit' in data:
                    exploit_refs = data['exploit']
                    if isinstance(exploit_refs, list):
                        exploits.extend([ref for ref in exploit_refs if ref.startswith('http')])
                    elif isinstance(exploit_refs, str) and exploit_refs.startswith('http'):
                        exploits.append(exploit_refs)
                        
        except Exception as e:
            print(f"     ⚠️ Error en CIRCL API: {e}")
        
        return exploits

    def search_nvd_references(self, cve_id):
        """Buscar exploits en referencias de NVD"""
        exploits = []
        
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    references = vuln.get('references', [])
                    
                    for ref in references:
                        ref_url = ref.get('url', '')
                        tags = ref.get('tags', [])
                        
                        # Buscar URLs con etiquetas relevantes
                        if any(tag.lower() in ['exploit', 'patch', 'third-party-advisory'] for tag in tags):
                            if ref_url.startswith('http'):
                                exploits.append(ref_url)
                        
                        # Buscar URLs que contengan palabras clave
                        elif any(keyword in ref_url.lower() for keyword in ['exploit', 'poc', 'security']):
                            if ref_url.startswith('http'):
                                exploits.append(ref_url)
                                
        except Exception as e:
            print(f"     ⚠️ Error en referencias NVD: {e}")
        
        return exploits

    def validate_exploit_url(self, url):
        """Validar que la URL sea relevante y accesible"""
        if not url or not url.startswith('http'):
            return False
        
        # URLs conocidas como válidas
        valid_domains = [
            'exploit-db.com',
            'github.com',
            'packetstormsecurity.com',
            'seclists.org',
            'cve.mitre.org',
            'nvd.nist.gov'
        ]
        
        # Verificar que sea de un dominio confiable
        if any(domain in url.lower() for domain in valid_domains):
            return True
        
        # URLs que definitivamente no son exploits
        invalid_patterns = [
            '/search?',
            '/about',
            '/contact',
            '/features',
            '/pricing',
            '/login',
            '/register'
        ]
        
        return not any(pattern in url.lower() for pattern in invalid_patterns)

    def get_details_links(self, cve_id):
        """Generar enlaces a detalles de CVE"""
        cvedetails_url = f"https://www.cvedetails.com/cve/{cve_id}/"
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        # Mostrar URLs completas en lugar de texto abreviado
        details_text = f"{cvedetails_url}\n{nvd_url}"
        
        return details_text, cvedetails_url, nvd_url