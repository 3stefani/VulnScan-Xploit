#!/usr/bin/env python3
"""
Escáner Avanzado de Vulnerabilidades y Exploits
===============================================

Aplicación principal que coordina el escaneo de vulnerabilidades
y la generación de reportes utilizando múltiples fuentes de datos.

Fuentes utilizadas:
- NVD (National Vulnerability Database)
- Exploit-DB (Base de datos local)
- CIRCL CVE Search API
- Referencias oficiales NVD
- CVEDetails para información detallada

Autor: 3stefani
Versión: 1.0
"""

import time
from rich.console import Console

from vuln_scanner import VulnScanner
from report_generator import ReportGenerator


def print_banner():
    """Mostrar banner de la aplicación"""
    console = Console()
    
    console.print("⭐ [bold red]VULN SCAN & XPLOIT[/bold red]⭐")
    console.print("=" * 60)
    console.print("📚 Fuentes utilizadas:")
    console.print("   • [cyan]NVD (National Vulnerability Database)[/cyan]")
    console.print("   • [yellow]Exploit-DB (Base de datos local)[/yellow]")
    console.print("   • [green]CIRCL CVE Search API[/green]")
    console.print("   • [blue]Referencias oficiales NVD[/blue]")
    console.print("   • [bright_blue]CVEDetails para información detallada[/bright_blue]")


def show_examples():
    """Mostrar ejemplos de búsqueda"""
    console = Console()
    
    console.print(f"\n💡 [bold]Ejemplos de búsqueda:[/bold]")
    examples = [
        "wordpress", "apache httpd", "mysql", "nginx", 
        "php", "windows server", "linux kernel", "openssh"
    ]
    for i, example in enumerate(examples, 1):
        console.print(f"   {i}. {example}")


def get_user_input():
    """Obtener entrada del usuario con validación"""
    service = input("\n✋ Ingrese el servicio/software a analizar: ").strip()
    
    if not service:
        console = Console()
        console.print("❌ [red]Error: Debe ingresar un servicio para buscar.[/red]")
        return None
    
    return service


def run_analysis(service):
    """Ejecutar análisis de vulnerabilidades"""
    console = Console()
    scanner = VulnScanner()
    report_generator = ReportGenerator()
    
    console.print(f"\n⚡ [bold]Iniciando análisis completo para: '{service}'[/bold]")
    console.print("⏳ [dim]Este proceso puede tomar unos minutos...[/dim]")
    console.print("=" * 60)
    
    start_time = time.time()
    
    try:
        # Ejecutar escaneo
        cves = scanner.search_cves(service)
        end_time = time.time()
        
        # Procesar resultados
        if isinstance(cves, str):
            # Error en el escaneo
            console.print(f"❌ [red]Error: {cves}[/red]")
            return False
            
        elif not cves:
            # No se encontraron vulnerabilidades
            console.print("❌ [yellow]No se encontraron vulnerabilidades para este servicio.[/yellow]")
            console.print("💡 [dim]Intente con términos más específicos o versiones del software.[/dim]")
            return False
            
        else:
            # Generar reporte exitoso
            console.print(f"\n✅ [green]Análisis completado en {end_time - start_time:.1f} segundos[/green]")
            report_generator.generate_report(cves)
            return True
            
    except KeyboardInterrupt:
        console.print("\n⚠️ [yellow]Análisis interrumpido por el usuario.[/yellow]")
        return False
        
    except Exception as e:
        console.print(f"\n❌ [red]Error inesperado: {str(e)}[/red]")
        console.print("💡 [dim]Si el problema persiste, verifique su conexión a internet.[/dim]")
        return False


def ask_for_another_scan():
    """Preguntar si el usuario quiere realizar otro escaneo"""
    console = Console()
    
    while True:
        choice = input("\n❓ ¿Desea realizar otro escaneo? (s/n): ").strip().lower()
        
        if choice in ['s', 'si', 'yes', 'y']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            console.print("❌ [red]Por favor, responda 's' para sí o 'n' para no.[/red]")


def main():
    """Función principal de la aplicación"""
    console = Console()
    
    try:
        # Mostrar banner y ejemplos
        print_banner()
        show_examples()
        
        # Bucle principal de la aplicación
        while True:
            # Obtener entrada del usuario
            service = get_user_input()
            if not service:
                continue
            
            # Ejecutar análisis
            success = run_analysis(service)
            
            # Preguntar si quiere continuar solo si el análisis fue exitoso
            if success:
                if not ask_for_another_scan():
                    break
            else:
                # En caso de error, dar opción de intentar de nuevo
                if not ask_for_another_scan():
                    break
        
        # Mensaje de despedida
        console.print("\n✨ [bold green]¡Gracias por usar el Escáner de Vulnerabilidades![/bold green] ✨")
        console.print("🛡️ [dim]Recuerde mantener sus sistemas actualizados y seguros.[/dim]")
        
    except KeyboardInterrupt:
        console.print("\n\n [bold yellow]Aplicación terminada por el usuario.[/bold yellow]")
        console.print("🛡️ [dim]¡Manténgase seguro![/dim]")
        
    except Exception as e:
        console.print(f"\n❌ [bold red]Error crítico en la aplicación: {str(e)}[/bold red]")
        console.print("💡 [dim]Si el problema persiste, contacte al administrador.[/dim]")


if __name__ == "__main__":
    main()