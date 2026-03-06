import os
import sys
import json
import time
import asyncio
import argparse
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.live import Live

# Configuration
VERSION = "2.1.0"
BANNER = f"""
[bold red]
██╗   ██╗██╗ ██████╗ ██╗██╗      █████╗ ███╗   ██╗ ██████╗███████╗
██║   ██║██║██╔════╝ ██║██║     ██╔══██╗████╗  ██║██╔════╝██╔════╝
██║   ██║██║██║  ███╗██║██║     ███████║██╔██╗ ██║██║     █████╗  
╚██╗ ██╔╝██║██║   ██║██║██║     ██╔══██║██║╚██╗██║██║     ██╔══╝  
 ╚████╔╝ ██║╚██████╔╝██║███████╗██║  ██║██║ ╚████║╚██████╗███████╗
  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
[/bold red]
[bold white]VIGILANCE PRO - Advanced Security Scanner & AI Auditor[/bold white]
[dim]Professional Security Analysis for Kali Linux | v{VERSION}[/dim]
"""

console = Console()

class VigilanceScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VigilanceScanner/2.1 (Kali Linux; Professional Security Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        })

    async def scan_target(self, url: str) -> Dict[str, Any]:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status": 0,
            "headers": {},
            "discovery": [],
            "content": {},
            "cookies": [],
            "scan_time_ms": 0
        }

        start_time = time.time()
        
        try:
            # 1. Main Page Scan
            response = self.session.get(url, timeout=20, verify=False)
            results["status"] = response.status_code
            results["headers"] = dict(response.headers)
            html = response.text

            # 2. Content Analysis
            results["content"] = {
                "has_forms": "<form" in html,
                "has_password_fields": 'type="password"' in html,
                "has_scripts": "<script" in html,
                "potential_xss_inputs": html.count("<input"),
                "meta_tags": html.count("<meta"),
                "links": html.count('href="')
            }

            # 3. Cookie Analysis
            for cookie in response.cookies:
                results["cookies"].append({
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "http_only": "httponly" in str(cookie).lower(),
                    "same_site": "samesite" in str(cookie).lower()
                })

            # 4. Path Discovery
            sensitive_paths = [
                "/admin", "/login", "/config", "/.env", "/.git/config", 
                "/wp-admin", "/phpmyadmin", "/api/v1/users", "/backup",
                "/server-status", "/.ssh/id_rsa", "/docker-compose.yml"
            ]
            
            base_url = f"{response.url.scheme}://{response.url.netloc}"
            
            for path in sensitive_paths:
                try:
                    path_url = f"{base_url}{path}"
                    path_res = self.session.head(path_url, timeout=5)
                    results["discovery"].append({
                        "path": path,
                        "status": path_res.status_code,
                        "accessible": path_res.status_code == 200
                    })
                except:
                    pass

            results["scan_time_ms"] = int((time.time() - start_time) * 1000)
            return results

        except Exception as e:
            console.print(f"[bold red]Error during scan:[/bold red] {str(e)}")
            return results

    async def generate_ai_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = f"""
        Analyze the following web security scan data for a professional penetration testing report.
        Focus specifically on OWASP Top 10 categories.
        
        Target Data:
        - URL: {data['url']}
        - Status: {data['status']}
        - Security Headers: {json.dumps(data['headers'])}
        - Discovered Paths: {json.dumps(data['discovery'])}
        - Content Analysis: {json.dumps(data['content'])}
        - Cookie Security: {json.dumps(data['cookies'])}

        Return a JSON object with:
        - summary: A high-level executive summary.
        - vulnerabilities: Array of {{severity, title, description, recommendation, category}}.
        - score: Security score (0-100).
        """

        try:
            response = self.model.generate_content(prompt)
            # Clean potential markdown formatting from JSON response
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:-3].strip()
            return json.loads(text)
        except Exception as e:
            return {
                "summary": f"AI Analysis failed: {str(e)}",
                "vulnerabilities": [],
                "score": 0
            }

async def main():
    parser = argparse.ArgumentParser(description="Vigilance PRO - AI Security Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--key", help="Gemini API Key (or set GEMINI_API_KEY env var)")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    api_key = args.key or os.getenv("GEMINI_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/bold red] API Key required. Use --key or GEMINI_API_KEY environment variable.")
        sys.exit(1)

    console.print(BANNER)
    console.print(f"[bold blue]Target:[/bold blue] {args.url}")
    console.print(f"[bold blue]Time:[/bold blue] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print("-" * 60)

    scanner = VigilanceScanner(api_key)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        # Step 1: Scanning
        task1 = progress.add_task(description="Performing deep scan...", total=None)
        scan_data = await scanner.scan_target(args.url)
        progress.update(task1, completed=True)
        
        # Step 2: AI Analysis
        task2 = progress.add_task(description="Generating AI security audit...", total=None)
        report = await scanner.generate_ai_report(scan_data)
        progress.update(task2, completed=True)

    # Display Results
    # 1. Header Analysis
    header_table = Table(title="Security Headers", show_header=True, header_style="bold magenta")
    header_table.add_column("Header")
    header_table.add_column("Status")
    
    important_headers = [
        "Content-Security-Policy", "Strict-Transport-Security", 
        "X-Frame-Options", "X-Content-Type-Options"
    ]
    
    for h in important_headers:
        status = "[green]PRESENT[/green]" if h.lower() in [k.lower() for k in scan_data['headers'].keys()] else "[red]MISSING[/red]"
        header_table.add_row(h, status)
    
    console.print(header_table)

    # 2. Vulnerabilities
    console.print("\n[bold yellow]VULNERABILITY ASSESSMENT[/bold yellow]")
    for v in report.get('vulnerabilities', []):
        color = "red" if v['severity'] in ['critical', 'high'] else "yellow"
        console.print(Panel(
            f"[bold]{v['title']}[/bold]\n"
            f"[dim]Category: {v['category']} | Severity: {v['severity'].upper()}[/dim]\n\n"
            f"{v['description']}\n\n"
            f"[bold green]Recommendation:[/bold green] {v['recommendation']}",
            border_style=color,
            title=v['severity'].upper()
        ))

    # 3. Final Score
    score = report.get('score', 0)
    score_color = "green" if score > 70 else "yellow" if score > 40 else "red"
    console.print(f"\n[bold]FINAL SECURITY SCORE:[/bold] [{score_color}]{score}/100[/{score_color}]")
    console.print(f"[dim]Scan completed in {scan_data['scan_time_ms']}ms[/dim]")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({"scan": scan_data, "report": report}, f, indent=4)
        console.print(f"\n[bold green]Report saved to {args.output}[/bold green]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan aborted by user.[/yellow]")
        sys.exit(0)
