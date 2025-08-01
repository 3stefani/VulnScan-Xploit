from rich.console import Console
from rich.table import Table


class ReportGenerator:
    """
    Generador de reportes visuales para el escáner de vulnerabilidades.
    Utiliza Rich para crear tablas formateadas y estadísticas.
    """
    
    def __init__(self):
        self.console = Console()
    
    def get_cvss_value(self, cve):
        """Extraer valor numérico de CVSS"""
        cvss = cve.get('cvss', 0)
        return float(cvss) if isinstance(cvss, (int, float)) else 0.0
    
    def format_cvss_display(self, cvss_value):
        """Formatear CVSS con colores según severidad"""
        if cvss_value >= 9.0:
            return f"[red bold]{cvss_value:.1f}[/red bold]"
        elif cvss_value >= 7.0:
            return f"[red]{cvss_value:.1f}[/red]"
        elif cvss_value >= 4.0:
            return f"[yellow]{cvss_value:.1f}[/yellow]"
        elif cvss_value > 0:
            return f"[green]{cvss_value:.1f}[/green]"
        else:
            return "N/A"
    
    def format_date(self, date_str):
        """Formatear fecha de publicación"""
        if date_str != 'N/A' and 'T' in date_str:
            return date_str.split('T')[0]
        return date_str
    
    def format_exploit_indicator(self, cve):
        """Crear indicador visual de exploits disponibles"""
        if cve.get('exploits_available', False):
            exploit_count = cve.get('exploit_count', len(cve.get('exploit_urls', [])))
            return f"👻 {exploit_count}"
        else:
            return "❌ 0"
    
    def format_exploit_urls(self, cve, max_urls=3):
        """Formatear URLs de exploits para mostrar en tabla"""
        exploit_urls_display = ""
        if cve.get('exploit_urls'):
            urls = cve['exploit_urls'][:max_urls]
            for i, url in enumerate(urls):
                exploit_urls_display += url
                if i < len(urls) - 1:
                    exploit_urls_display += "\n"
            
            if len(cve['exploit_urls']) > max_urls:
                exploit_urls_display += f"\n+{len(cve['exploit_urls']) - max_urls} más URLs"
        else:
            exploit_urls_display = "N/A"
        
        return exploit_urls_display
    
    def truncate_description(self, description, max_length=120):
        """Truncar descripción para ajustar en tabla"""
        if len(description) > max_length:
            return description[:max_length-3] + "..."
        return description
    
    def sort_cves(self, cves_details):
        """Ordenar CVEs por prioridad: exploits disponibles, CVSS, fecha"""
        return sorted(
            cves_details,
            key=lambda x: (
                x.get('exploits_available', False),
                self.get_cvss_value(x),
                x.get('published', '')
            ),
            reverse=True
        )
    
    def calculate_statistics(self, cves_details):
        """Calcular estadísticas del análisis"""
        total_cves = len(cves_details)
        with_exploits = sum(1 for cve in cves_details if cve.get('exploits_available', False))
        high_risk = sum(1 for cve in cves_details if self.get_cvss_value(cve) >= 7.0)
        
        return {
            'total': total_cves,
            'with_exploits': with_exploits,
            'high_risk': high_risk,
            'without_exploits': total_cves - with_exploits
        }
    
    def create_main_table(self, cves_details_sorted):
        """Crear tabla principal con resultados"""
        table = Table(title="🔍 Escáner de Vulnerabilidades con Exploits Verificados")
        
        table.add_column("CVE ID", style="cyan", no_wrap=True, width=15)
        table.add_column("Descripción", style="magenta", max_width=40)
        table.add_column("CVSS", style="green", justify="center", width=8)
        table.add_column("Publicado", style="blue", width=12)
        table.add_column("Exploits", style="red bold", justify="center", width=10)
        table.add_column("URLs de Exploits", style="yellow", max_width=45)
        table.add_column("Detalles", style="bright_blue", max_width=50)
        
        for cve in cves_details_sorted:
            # Formatear todos los campos
            cve_id = cve.get('cve_id', 'N/A')
            description = self.truncate_description(cve.get('description', 'No disponible'))
            cvss_display = self.format_cvss_display(self.get_cvss_value(cve))
            published = self.format_date(cve.get('published', 'N/A'))
            exploit_indicator = self.format_exploit_indicator(cve)
            exploit_urls_display = self.format_exploit_urls(cve)
            
            # Generar enlaces de detalles
            from vuln_scanner import VulnScanner  # Import local para evitar circular
            scanner = VulnScanner()
            details_links, _, _ = scanner.get_details_links(cve_id)
            
            table.add_row(
                cve_id,
                description,
                cvss_display,
                published,
                exploit_indicator,
                exploit_urls_display,
                details_links
            )
        
        return table
    
    def print_statistics(self, stats):
        """Mostrar resumen estadístico"""
        self.console.print(f"\n📚 [bold]Resumen del Análisis:[/bold]")
        self.console.print(f"   • Total de CVEs: [cyan]{stats['total']}[/cyan]")
        self.console.print(f"   • Con exploits disponibles: [red bold]{stats['with_exploits']}[/red bold]")
        self.console.print(f"   • Alto riesgo (CVSS ≥ 7.0): [orange3]{stats['high_risk']}[/orange3]")
        self.console.print(f"   • Sin exploits conocidos: [green]{stats['without_exploits']}[/green]")
    
    def print_links_info(self):
        """Mostrar información sobre los enlaces"""
        self.console.print(f"\n🔗 [bold]Columnas de Enlaces:[/bold]")
        self.console.print("   • [yellow]URLs de Exploits[/yellow]: Enlaces directos a exploits públicos")
        self.console.print("   • [bright_blue]Detalles[/bright_blue]: URLs completas a CVEDetails y NVD")
        self.console.print("   [dim]💡 Puedes copiar y pegar las URLs directamente[/dim]")
    
    def print_security_alerts(self, cves_details_sorted, stats):
        """Mostrar alertas de seguridad críticas"""
        if stats['with_exploits'] > 0:
            self.console.print(f"\n🚨 [bold red]ALERTA DE SEGURIDAD CRÍTICA[/bold red]")
            self.console.print(f"   Se encontraron [red bold]{stats['with_exploits']}[/red bold] vulnerabilidades con exploits públicos.")
            self.console.print("   [red]¡Requieren atención inmediata![/red]")
            
            # Mostrar URLs completas
            self.console.print(f"\n🔗 [bold]Enlaces completos a exploits y detalles:[/bold]")
            for cve in cves_details_sorted:
                if cve.get('exploits_available') and cve.get('exploit_urls'):
                    cve_id = cve['cve_id']
                    cvss_value = self.get_cvss_value(cve)
                    self.console.print(f"\n   • [cyan bold]{cve_id}[/cyan bold] (CVSS: {cvss_value:.1f}):")
                    
                    # Enlaces de detalles
                    from vuln_scanner import VulnScanner
                    scanner = VulnScanner()
                    _, cvedetails_url, nvd_url = scanner.get_details_links(cve_id)
                    self.console.print(f"     [bright_blue]📋 Detalles CVE:[/bright_blue]")
                    self.console.print(f"       → [link={cvedetails_url}]{cvedetails_url}[/link]")
                    self.console.print(f"       → [link={nvd_url}]{nvd_url}[/link]")
                    
                    # Enlaces de exploits
                    self.console.print(f"     [red]👻 Exploits:[/red]")
                    for url in cve['exploit_urls']:
                        self.console.print(f"       → [yellow]{url}[/yellow]")
    
    def print_recommendations(self, stats):
        """Mostrar recomendaciones de seguridad"""
        self.console.print(f"\n💡 [bold]Recomendaciones:[/bold]")
        if stats['high_risk'] > 0:
            self.console.print("   1. [red]Priorizar parches para vulnerabilidades CVSS ≥ 7.0[/red]")
        if stats['with_exploits'] > 0:
            self.console.print("   2. [red]Implementar controles de seguridad adicionales[/red]")
        self.console.print("   3. [yellow]Consultar enlaces de detalles para más información[/yellow]")
        self.console.print("   4. [yellow]Monitorear continuamente nuevas vulnerabilidades[/yellow]")
        self.console.print("   5. [green]Mantener sistemas actualizados[/green]")
    
    def generate_report(self, cves_details):
        """Generar reporte completo"""
        # Ordenar CVEs
        cves_details_sorted = self.sort_cves(cves_details)
        
        # Calcular estadísticas
        stats = self.calculate_statistics(cves_details_sorted)
        
        # Crear y mostrar tabla principal
        table = self.create_main_table(cves_details_sorted)
        self.console.print(table)
        
        # Mostrar estadísticas
        self.print_statistics(stats)
        
        # Mostrar información de enlaces
        self.print_links_info()
        
        # Mostrar alertas de seguridad
        self.print_security_alerts(cves_details_sorted, stats)
        
        # Mostrar recomendaciones
        self.print_recommendations(stats)