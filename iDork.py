#!/usr/bin/env python3
"""
iDork v2.0 - User-Friendly Interactive Dorking Framework
Developed by: root (@rootbck)
No command line arguments needed - fully interactive!
"""

import os
import sys
import time
import json
import csv
import random
import threading
import re
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from typing import List, Dict, Optional, Union

# Check for tkinter (for file picker)
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox

    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.layout import Layout
    from rich.live import Live
    from rich.tree import Tree
    from rich.text import Text
    from rich.align import Align
except ImportError:
    print("❌ Error: 'rich' library not found. Install with: pip install rich")
    sys.exit(1)

try:
    from duckduckgo_search import DDGS
except ImportError:
    print("❌ Error: 'duckduckgo-search' library not found. Install with: pip install duckduckgo-search")
    sys.exit(1)

try:
    from googlesearch import search as google_search
except ImportError:
    google_search = None

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("❌ Error: 'requests' library not found. Install with: pip install requests")
    sys.exit(1)

console = Console()

# Enhanced ASCII Logo
ASCII_LOGO = """
     ╔═══════════════════════════════════════╗
     ║    ██╗██████╗  ██████╗ ██████╗ ██╗  ██╗║
     ║    ██║██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝║
     ║    ██║██║  ██║██║   ██║██████╔╝█████╔╝ ║
     ║    ██║██║  ██║██║   ██║██╔══██╗██╔═██╗ ║
     ║    ██║██████╔╝╚██████╔╝██║  ██║██║  ██╗║
     ║    ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝║
     ║    🌟 USER-FRIENDLY INTERACTIVE MODE 🌟  ║
     ╚═══════════════════════════════════════╝

     [bold red]ᵛ²ˑ⁰ - No Commands Needed! 🎯[/bold red]
     [bold green]Developer: root | TG: @rootbck[/bold green]
"""

WELCOME_MESSAGE = """
[bold cyan]🎉 Welcome to iDork v2.0![/bold cyan]

This is the user-friendly version - no complex commands needed!
Just follow the simple prompts and let iDork guide you through everything.

[bold yellow]✨ Features:[/bold yellow]
• 🔍 Multiple search engines (Google, Bing, Yahoo, DuckDuckGo, Yandex)
• 📁 Easy file picker for dork lists
• 🔒 Optional proxy support
• 💾 Multiple output formats
• ✅ URL verification
• 📊 Beautiful statistics

[bold green]Let's get started! 🚀[/bold green]
"""


# File picker function
def open_file_picker(title="Select File", filetypes=None):
    """Open a file picker dialog"""
    if not TKINTER_AVAILABLE:
        return None

    if filetypes is None:
        filetypes = [("Text files", "*.txt"), ("All files", "*.*")]

    try:
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        root.lift()
        root.attributes('-topmost', True)

        filename = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes
        )

        root.destroy()
        return filename if filename else None
    except Exception as e:
        console.print(f"[red]❌ File picker error: {e}[/red]")
        return None


def save_file_picker(title="Save As", defaultextension=".txt", filetypes=None):
    """Open a save file dialog"""
    if not TKINTER_AVAILABLE:
        return None

    if filetypes is None:
        filetypes = [("Text files", "*.txt"), ("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]

    try:
        root = tk.Tk()
        root.withdraw()
        root.lift()
        root.attributes('-topmost', True)

        filename = filedialog.asksaveasfilename(
            title=title,
            defaultextension=defaultextension,
            filetypes=filetypes
        )

        root.destroy()
        return filename if filename else None
    except Exception as e:
        console.print(f"[red]❌ Save dialog error: {e}[/red]")
        return None


# REPLACE the SimpleConfig class with this enhanced version:

class SimpleConfig:
    """Enhanced configuration for better rate limiting"""

    def __init__(self):
        self.config = {
            "default_output_dir": str(Path.home() / "iDork_Results"),
            "max_results_per_query": 100,
            "request_delay": 8.0,  # Increased base delay
            "supported_engines": ["duckduckgo", "google", "bing", "yahoo", "yandex"],
            "user_agents": [
                # More realistic user agents
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
            ],
            "rate_limit_delay": 15.0,  # Increased rate limit delay
            "max_retries": 3,  # Reduced retries to avoid long waits
            "engine_delays": {  # Different delays per engine
                "duckduckgo": 8.0,
                "google": 12.0,
                "bing": 6.0,
                "yahoo": 7.0,
                "yandex": 5.0
            }
        }
class ProxyManager:
    """Simple proxy manager"""

    def __init__(self, proxies=None):
        self.proxies = proxies or []
        self.current_index = 0
        self.failed_proxies = set()

    def get_proxy(self):
        """Get next working proxy"""
        if not self.proxies:
            return None

        available = [p for p in self.proxies if p not in self.failed_proxies]
        if not available:
            self.failed_proxies.clear()
            available = self.proxies

        if available:
            proxy = available[self.current_index % len(available)]
            self.current_index += 1
            return {"http": proxy, "https": proxy}
        return None

    def mark_failed(self, proxy_dict):
        """Mark proxy as failed"""
        if proxy_dict and "http" in proxy_dict:
            self.failed_proxies.add(proxy_dict["http"])


# REPLACE CHUNK 2 - Enhanced Search Engine with URL Counter and Working Engines

class SimpleSearchEngine:
    """Enhanced search engine manager with real-time URL counter"""

    def __init__(self, config, proxy_manager=None):
        self.config = config
        self.proxy_manager = proxy_manager
        self.session = self._create_session()
        self.last_request = {}
        self.total_urls_found = 0  # URL counter

    def _create_session(self):
        """Create requests session with better headers"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(self.config["user_agents"]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8,de;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })

        retry_strategy = Retry(
            total=3,
            backoff_factor=3,
            status_forcelist=[429, 500, 502, 503, 504, 202]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _wait_for_rate_limit(self, engine):
        """Enhanced rate limiting with random delays"""
        current_time = time.time()
        last_time = self.last_request.get(engine, 0)

        # Base delay + random component to avoid patterns
        base_delay = self.config["request_delay"]
        random_delay = random.uniform(1, 3)
        total_delay = base_delay + random_delay

        if current_time - last_time < total_delay:
            wait_time = total_delay - (current_time - last_time)
            console.print(
                f"[yellow]⏱️ Waiting {wait_time:.1f}s for {engine}... (URLs found so far: {self.total_urls_found})[/yellow]")
            time.sleep(wait_time)

        self.last_request[engine] = time.time()

    def search_duckduckgo(self, query, max_results=100):
        """Enhanced DuckDuckGo search with better error handling"""
        results = []
        retries = 0
        max_retries = self.config["max_retries"]

        while retries < max_retries:
            try:
                self._wait_for_rate_limit("duckduckgo")
                proxy_config = self.proxy_manager.get_proxy() if self.proxy_manager else None

                # Try different regions and safesearch settings
                regions = ['us-en', 'uk-en', 'ca-en', 'au-en']
                region = random.choice(regions)

                with DDGS(proxies=proxy_config) as ddgs:
                    search_results = ddgs.text(
                        query,
                        max_results=max_results,
                        region=region,
                        safesearch='off',
                        timelimit=None
                    )

                    for result in search_results:
                        url = result.get("href") or result.get("url")
                        if url and url.startswith(('http://', 'https://')):
                            results.append({
                                "url": url,
                                "title": result.get("title", ""),
                                "snippet": result.get("body", ""),
                                "engine": "duckduckgo"
                            })
                            self.total_urls_found += 1

                if results:
                    console.print(f"[green]✅ Found {len(results)} URLs! (Total: {self.total_urls_found})[/green]")
                else:
                    console.print(
                        f"[yellow]⚠️ No results for this query (Total URLs: {self.total_urls_found})[/yellow]")
                break  # Success

            except Exception as e:
                retries += 1
                error_str = str(e).lower()

                if any(x in error_str for x in ["ratelimit", "429", "202", "timeout"]):
                    wait_time = self.config["rate_limit_delay"] * (retries ** 2)  # Exponential backoff
                    console.print(
                        f"[red]🚫 Rate limited! Waiting {wait_time}s (attempt {retries}/{max_retries}) - URLs found: {self.total_urls_found}[/red]")
                    time.sleep(wait_time)
                else:
                    console.print(
                        f"[red]❌ DuckDuckGo error (attempt {retries}): {e} - URLs so far: {self.total_urls_found}[/red]")
                    if retries < max_retries:
                        time.sleep(5 * retries)

        return results

    def search_google(self, query, max_results=100):
        """Enhanced Google search"""
        results = []
        if not google_search:
            console.print("[yellow]⚠️ Google search requires: pip install googlesearch-python[/yellow]")
            return results

        try:
            self._wait_for_rate_limit("google")

            # Use smaller batches for Google to avoid rate limits
            batch_size = min(max_results, 20)

            search_results = google_search(
                query,
                num_results=batch_size,
                sleep_interval=random.uniform(8, 15),  # Longer delays for Google
                lang='en',
                safe='off',
                pause=random.uniform(2, 5)
            )

            for i, url in enumerate(search_results):
                if i >= max_results:
                    break
                if url and url.startswith(('http://', 'https://')):
                    results.append({
                        "url": url,
                        "title": f"Google Result {i + 1}",
                        "snippet": "",
                        "engine": "google"
                    })
                    self.total_urls_found += 1

            if results:
                console.print(
                    f"[green]✅ Found {len(results)} URLs from Google! (Total: {self.total_urls_found})[/green]")
            else:
                console.print(f"[yellow]⚠️ No Google results (Total URLs: {self.total_urls_found})[/yellow]")

        except Exception as e:
            console.print(f"[red]❌ Google search error: {e} - URLs so far: {self.total_urls_found}[/red]")

        return results

    def search_bing(self, query, max_results=100):
        """Working Bing search implementation"""
        results = []
        try:
            self._wait_for_rate_limit("bing")

            headers = {
                'User-Agent': random.choice(self.config["user_agents"]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1'
            }

            proxy_config = self.proxy_manager.get_proxy() if self.proxy_manager else None

            # Search multiple pages
            for page in range(0, min(max_results, 50), 10):
                if len(results) >= max_results:
                    break

                search_url = f"https://www.bing.com/search?q={requests.utils.quote(query)}&first={page}&count=10"

                try:
                    response = self.session.get(
                        search_url,
                        headers=headers,
                        proxies=proxy_config,
                        timeout=15
                    )

                    if response.status_code == 200:
                        # Extract URLs using regex
                        import re
                        url_pattern = r'<a[^>]+href="(https?://[^"]+)"[^>]*>'
                        urls = re.findall(url_pattern, response.text)

                        page_results = 0
                        for url in urls:
                            if len(results) >= max_results:
                                break
                            # Filter out Bing internal URLs
                            if not any(x in url.lower() for x in ['bing.com', 'microsoft.com', 'msn.com']):
                                # Clean URL
                                if '&amp;' in url:
                                    url = url.split('&amp;')[0]

                                results.append({
                                    "url": url,
                                    "title": f"Bing Result {len(results) + 1}",
                                    "snippet": "",
                                    "engine": "bing"
                                })
                                self.total_urls_found += 1
                                page_results += 1

                        if page_results == 0:
                            break  # No more results

                        # Delay between pages
                        time.sleep(random.uniform(2, 4))

                    else:
                        console.print(f"[yellow]⚠️ Bing returned status {response.status_code}[/yellow]")
                        break

                except Exception as e:
                    console.print(f"[yellow]⚠️ Bing page error: {e}[/yellow]")
                    break

            if results:
                console.print(f"[green]✅ Found {len(results)} URLs from Bing! (Total: {self.total_urls_found})[/green]")
            else:
                console.print(f"[yellow]⚠️ No Bing results (Total URLs: {self.total_urls_found})[/yellow]")

        except Exception as e:
            console.print(f"[red]❌ Bing search error: {e} - URLs so far: {self.total_urls_found}[/red]")

        return results

    def search_yahoo(self, query, max_results=100):
        """Working Yahoo search implementation"""
        results = []
        try:
            self._wait_for_rate_limit("yahoo")

            headers = {
                'User-Agent': random.choice(self.config["user_agents"]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://search.yahoo.com/'
            }

            proxy_config = self.proxy_manager.get_proxy() if self.proxy_manager else None

            # Search multiple pages
            for page in range(1, min(max_results // 10 + 2, 6)):
                if len(results) >= max_results:
                    break

                start = (page - 1) * 10 + 1
                search_url = f"https://search.yahoo.com/search?p={requests.utils.quote(query)}&b={start}&pz=10"

                try:
                    response = self.session.get(
                        search_url,
                        headers=headers,
                        proxies=proxy_config,
                        timeout=15
                    )

                    if response.status_code == 200:
                        # Extract URLs
                        import re
                        # Yahoo uses specific URL patterns
                        url_pattern = r'href="(https?://[^"]+)"[^>]*class="[^"]*ac-algo[^"]*"'
                        urls = re.findall(url_pattern, response.text)

                        page_results = 0
                        for url in urls:
                            if len(results) >= max_results:
                                break
                            # Filter out Yahoo internal URLs
                            if not any(x in url.lower() for x in ['yahoo.com', 'verizonmedia.com']):
                                results.append({
                                    "url": url,
                                    "title": f"Yahoo Result {len(results) + 1}",
                                    "snippet": "",
                                    "engine": "yahoo"
                                })
                                self.total_urls_found += 1
                                page_results += 1

                        if page_results == 0:
                            break

                        time.sleep(random.uniform(3, 6))
                    else:
                        break

                except Exception as e:
                    console.print(f"[yellow]⚠️ Yahoo page error: {e}[/yellow]")
                    break

            if results:
                console.print(
                    f"[green]✅ Found {len(results)} URLs from Yahoo! (Total: {self.total_urls_found})[/green]")
            else:
                console.print(f"[yellow]⚠️ No Yahoo results (Total URLs: {self.total_urls_found})[/yellow]")

        except Exception as e:
            console.print(f"[red]❌ Yahoo search error: {e} - URLs so far: {self.total_urls_found}[/red]")

        return results

    def search_yandex(self, query, max_results=100):
        """Working Yandex search implementation"""
        results = []
        try:
            self._wait_for_rate_limit("yandex")

            headers = {
                'User-Agent': random.choice(self.config["user_agents"]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8'
            }

            proxy_config = self.proxy_manager.get_proxy() if self.proxy_manager else None

            # Search multiple pages
            for page in range(0, min(max_results, 50), 10):
                if len(results) >= max_results:
                    break

                search_url = f"https://yandex.com/search/?text={requests.utils.quote(query)}&p={page // 10}&lr=84"

                try:
                    response = self.session.get(
                        search_url,
                        headers=headers,
                        proxies=proxy_config,
                        timeout=15
                    )

                    if response.status_code == 200:
                        # Extract URLs
                        import re
                        url_pattern = r'href="(https?://[^"]+)"[^>]*class="[^"]*link[^"]*"'
                        urls = re.findall(url_pattern, response.text)

                        page_results = 0
                        for url in urls:
                            if len(results) >= max_results:
                                break
                            # Filter out Yandex internal URLs
                            if not any(x in url.lower() for x in ['yandex.', 'ya.ru']):
                                results.append({
                                    "url": url,
                                    "title": f"Yandex Result {len(results) + 1}",
                                    "snippet": "",
                                    "engine": "yandex"
                                })
                                self.total_urls_found += 1
                                page_results += 1

                        if page_results == 0:
                            break

                        time.sleep(random.uniform(2, 5))
                    else:
                        break

                except Exception as e:
                    console.print(f"[yellow]⚠️ Yandex page error: {e}[/yellow]")
                    break

            if results:
                console.print(
                    f"[green]✅ Found {len(results)} URLs from Yandex! (Total: {self.total_urls_found})[/green]")
            else:
                console.print(f"[yellow]⚠️ No Yandex results (Total URLs: {self.total_urls_found})[/yellow]")

        except Exception as e:
            console.print(f"[red]❌ Yandex search error: {e} - URLs so far: {self.total_urls_found}[/red]")

        return results

    def search(self, query, engine, max_results=100):
        """Enhanced main search interface with URL counter"""
        console.print(
            f"[cyan]🔍 Searching '{query[:50]}...' with {engine.title()} (URLs found: {self.total_urls_found})[/cyan]")

        search_methods = {
            "duckduckgo": self.search_duckduckgo,
            "google": self.search_google,
            "bing": self.search_bing,
            "yahoo": self.search_yahoo,
            "yandex": self.search_yandex
        }

        method = search_methods.get(engine.lower())
        if not method:
            console.print(f"[red]❌ Engine '{engine}' not supported[/red]")
            return []

        return method(query, max_results)

class DorkTemplates:
    """Pre-made dork templates for easy use"""

    def __init__(self):
        self.templates = {
            "🔑 Login Pages": [
                "inurl:login",
                "inurl:signin",
                "inurl:admin",
                "intext:login",
                "intext:username password"
            ],
            "📁 Config Files": [
                "filetype:conf",
                "filetype:config",
                "filetype:cfg",
                "filetype:ini"
            ],
            "💾 Backup Files": [
                "filetype:bak",
                "filetype:backup",
                "filetype:old",
                "filetype:sql"
            ],
            "📂 Directory Listings": [
                'intitle:"Index of"',
                '"Parent Directory"',
                'intitle:"directory listing"'
            ],
            "⚠️ Error Pages": [
                "intext:error",
                "intext:warning",
                "intext:fatal",
                "intext:mysql error"
            ],
            "🔒 Sensitive Files": [
                "filetype:pdf confidential",
                "filetype:doc password",
                "filetype:xls internal"
            ],
            "🗄️ Database Files": [
                "filetype:sql",
                "filetype:db",
                "filetype:mdb"
            ],
            "📝 Log Files": [
                "filetype:log",
                "inurl:log",
                "error.log",
                "access.log"
            ]
        }

    def get_categories(self):
        """Get list of template categories"""
        return list(self.templates.keys())

    def get_dorks(self, category):
        """Get dorks for a category"""
        return self.templates.get(category, [])

    def format_for_site(self, dorks, site):
        """Format dorks for specific site"""
        return [f"site:{site} {dork}" for dork in dorks]


class FileManager:
    """FIXED file manager with working auto-save functionality"""

    def __init__(self, output_dir=None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "iDork_Results"
        self.output_dir.mkdir(exist_ok=True)

        # Auto-save settings
        self.auto_save_enabled = True
        self.auto_save_interval = 50
        self.auto_save_files = {}
        self.results_buffer = []
        self.total_saved = 0
        self.save_counter = 0  # Track when to save

    def setup_auto_save(self, base_filename, formats=["txt"]):
        """Setup auto-save files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for format_type in formats:
            filename = f"{base_filename}_autosave_{timestamp}.{format_type}"
            filepath = self.output_dir / filename

            try:
                if format_type == "txt":
                    # Create header for TXT file
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write("iDork v2.0 - Live Search Results\n")
                        f.write("=" * 50 + "\n")
                        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Auto-save: Every {self.auto_save_interval} results\n")
                        f.write("=" * 50 + "\n\n")

                elif format_type == "json":
                    # Create initial JSON structure
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump({
                            "metadata": {
                                "tool": "iDork v2.0",
                                "started": datetime.now().isoformat(),
                                "auto_save": True,
                                "total_results": 0
                            },
                            "results": []
                        }, f, indent=2)

                elif format_type == "csv":
                    # Create CSV header
                    with open(filepath, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(["#", "URL", "Title", "Engine", "Query", "Timestamp"])

                self.auto_save_files[format_type] = filepath
                console.print(f"[green]🔄 Auto-save enabled: {filepath}[/green]")

            except Exception as e:
                console.print(f"[red]❌ Error setting up auto-save file ({format_type}): {e}[/red]")

    def auto_save_results(self, new_results, force=False):
        """ENHANCED auto-save with debug info"""
        console.print(
            f"[dim]🔧 auto_save_results called: {len(new_results)} new results, force={force}, enabled={self.auto_save_enabled}[/dim]")

        if not self.auto_save_enabled:
            console.print(f"[yellow]⚠️ Auto-save is disabled, skipping...[/yellow]")
            return

        if not new_results and not force:
            console.print(f"[dim]📊 No new results and not forcing, skipping...[/dim]")
            return

        # Add new results to buffer
        if new_results:
            self.results_buffer.extend(new_results)
            self.save_counter += len(new_results)
            console.print(
                f"[cyan]📝 Added {len(new_results)} results to buffer. Buffer size: {len(self.results_buffer)}, Counter: {self.save_counter}[/cyan]")

        # Save when we reach the interval or force save
        if self.save_counter >= self.auto_save_interval or force:
            console.print(
                f"[yellow]💾 Triggering save: counter={self.save_counter}, interval={self.auto_save_interval}, force={force}[/yellow]")
            self._flush_buffer()
            self.save_counter = 0  # Reset counter
        else:
            console.print(f"[dim]📊 Not saving yet: {self.save_counter}/{self.auto_save_interval} results[/dim]")

    def _flush_buffer(self):
        """FIXED: Flush buffer to files with better error handling"""
        if not self.results_buffer:
            console.print("[dim]📊 No results in buffer to flush[/dim]")
            return

        console.print(f"[cyan]💾 Saving {len(self.results_buffer)} results to auto-save files...[/cyan]")

        for format_type, filepath in self.auto_save_files.items():
            if filepath and filepath.exists():
                try:
                    self._append_to_file(filepath, self.results_buffer, format_type)
                    console.print(f"[green]✅ Saved to {format_type.upper()} file[/green]")
                except Exception as e:
                    console.print(f"[red]❌ Auto-save error ({format_type}): {e}[/red]")

        self.total_saved += len(self.results_buffer)
        console.print(
            f"[bold cyan]💾 Auto-saved {len(self.results_buffer)} results! Total saved: {self.total_saved}[/bold cyan]")
        self.results_buffer.clear()

    def _append_to_file(self, filepath, results, format_type):
        """FIXED: Append results to specific file format"""
        if format_type == "txt":
            with open(filepath, 'a', encoding='utf-8') as f:
                for i, result in enumerate(results):
                    result_num = self.total_saved + i + 1
                    url = result.get("url", "N/A")
                    title = result.get("title", "N/A")
                    engine = result.get("engine", "unknown")
                    query = result.get("query", "N/A")
                    timestamp = result.get("timestamp", "N/A")

                    f.write(f"{result_num}. [{engine.upper()}] {title}\n")
                    f.write(f"   URL: {url}\n")
                    f.write(f"   Query: {query}\n")
                    f.write(f"   Time: {timestamp}\n")
                    f.write("-" * 50 + "\n")

        elif format_type == "json":
            # Read existing JSON, append new results, write back
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                data["results"].extend(results)
                data["metadata"]["last_updated"] = datetime.now().isoformat()
                data["metadata"]["total_results"] = len(data["results"])

                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                console.print(f"[red]JSON save error: {e}[/red]")

        elif format_type == "csv":
            with open(filepath, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                for i, result in enumerate(results):
                    result_num = self.total_saved + i + 1
                    writer.writerow([
                        result_num,
                        result.get("url", ""),
                        result.get("title", ""),
                        result.get("engine", ""),
                        result.get("query", ""),
                        result.get("timestamp", "")
                    ])

    def finalize_auto_save(self):
        """Finalize auto-save files"""
        console.print("[blue]🔄 Finalizing auto-save files...[/blue]")

        # Flush any remaining results
        if self.results_buffer:
            self._flush_buffer()

        # Add footer to TXT file
        txt_file = self.auto_save_files.get("txt")
        if txt_file and txt_file.exists():
            try:
                with open(txt_file, 'a', encoding='utf-8') as f:
                    f.write("\n" + "=" * 50 + "\n")
                    f.write(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Results: {self.total_saved}\n")
                    f.write("=" * 50 + "\n")
            except Exception as e:
                console.print(f"[red]Error finalizing TXT file: {e}[/red]")

        console.print(f"[bold green]✅ Auto-save finalized! Total results saved: {self.total_saved}[/bold green]")

    def load_dorks_from_file(self, filepath):
        """Load dorks from file with multiple encoding support"""
        dorks = []
        encodings = ['utf-8', 'utf-16', 'latin1', 'cp1252', 'iso-8859-1']

        for encoding in encodings:
            try:
                with open(filepath, 'r', encoding=encoding) as f:
                    content = f.read()
                    console.print(f"[green]✅ File loaded using {encoding} encoding[/green]")
                    break
            except UnicodeDecodeError:
                continue
        else:
            console.print("[red]❌ Could not read file with any encoding[/red]")
            return dorks

        # Process lines
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if line and not line.startswith('#'):
                dorks.append(line)

        console.print(f"[green]✅ Loaded {len(dorks)} dorks from file[/green]")
        return dorks

    def save_results(self, results, filename=None, format_type="txt"):
        """Save final results to file (separate from auto-save)"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"idork_final_results_{timestamp}"

        filepath = self.output_dir / f"{filename}.{format_type}"

        try:
            if format_type == "json":
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump({
                        "metadata": {
                            "tool": "iDork v2.0",
                            "generated": datetime.now().isoformat(),
                            "total_results": len(results)
                        },
                        "results": results
                    }, f, indent=2, ensure_ascii=False)

            elif format_type == "csv":
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    if results:
                        writer = csv.DictWriter(f, fieldnames=results[0].keys())
                        writer.writeheader()
                        writer.writerows(results)

            else:  # txt format
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write("iDork v2.0 - Final Search Results\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Results: {len(results)}\n")
                    f.write("=" * 50 + "\n\n")

                    for i, result in enumerate(results, 1):
                        url = result.get("url", "N/A")
                        title = result.get("title", "N/A")
                        engine = result.get("engine", "unknown")

                        f.write(f"{i}. [{engine.upper()}] {title}\n")
                        f.write(f"   URL: {url}\n")
                        f.write(f"   Query: {result.get('query', 'N/A')}\n")
                        f.write("\n")

            console.print(f"[green]💾 Final results saved to: {filepath}[/green]")
            return str(filepath)

        except Exception as e:
            console.print(f"[red]❌ Error saving final file: {e}[/red]")
            return None

def run_search(self, dorks, engine, max_results):
    """Simplified search function - auto-save already configured"""
    console.print(f"\n[bold green]🚀 Starting Search[/bold green]")
    console.print(f"[cyan]Engine: {engine.title()}[/cyan]")
    console.print(f"[cyan]Dorks: {len(dorks)}[/cyan]")
    console.print(f"[cyan]Max results per dork: {max_results}[/cyan]")

    # Show auto-save status
    if self.file_manager.auto_save_enabled:
        console.print(f"[green]💾 Auto-save: Every {self.file_manager.auto_save_interval} results[/green]")
    else:
        console.print("[yellow]⚠️ Auto-save disabled[/yellow]")

    # Reset counters
    self.search_engine.total_urls_found = 0

    # Show warning for large searches
    if len(dorks) > 100:
        console.print(f"\n[yellow]⚠️ WARNING: {len(dorks)} dorks will take a long time![/yellow]")
        engine_delay = self.config.get("engine_delays", {}).get(engine, 8.0)
        estimated_time = len(dorks) * engine_delay / 60
        console.print(f"[yellow]Estimated time: {estimated_time:.1f} minutes[/yellow]")

        if self.file_manager.auto_save_enabled:
            console.print(f"[green]✅ Auto-save is enabled - progress will be preserved![/green]")

        if not Confirm.ask("Continue?", default=True):
            console.print("[yellow]Search cancelled by user[/yellow]")
            return []

    self.stats["start_time"] = datetime.now()
    self.stats["total_queries"] = len(dorks)
    all_results = []

    try:
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TextColumn("[bold green]URLs: {task.fields[urls_found]}[/bold green]"),
                TextColumn(
                    "[bold blue]Saved: {task.fields[saved_count]}[/bold blue]") if self.file_manager.auto_save_enabled else TextColumn(
                    ""),
                TimeElapsedColumn(),
                console=console
        ) as progress:

            task_fields = {"urls_found": 0}
            if self.file_manager.auto_save_enabled:
                task_fields["saved_count"] = 0

            search_task = progress.add_task(
                "Searching...",
                total=len(dorks),
                **task_fields
            )

            for i, dork in enumerate(dorks, 1):
                try:
                    # Update progress description
                    dork_preview = dork[:40] + "..." if len(dork) > 40 else dork
                    progress.update(search_task, description=f"Searching: {dork_preview}")

                    # Search with current engine
                    results = self.search_engine.search(dork, engine, max_results)

                    # Add metadata
                    for result in results:
                        result.update({
                            "query": dork,
                            "timestamp": datetime.now().isoformat(),
                            "query_number": i,
                            "dork_index": i
                        })

                    all_results.extend(results)
                    self.stats["successful_queries"] += 1

                    if results:
                        console.print(f"[cyan]📝 Adding {len(results)} results to auto-save buffer...[/cyan]")
                        self.file_manager.auto_save_results(results)

                    # # Auto-save new results
                    # if results and self.file_manager.auto_save_enabled:
                    #     self.file_manager.auto_save_results(results)

                    # Update progress
                    update_data = {
                        "urls_found": self.search_engine.total_urls_found,
                        "description": f"Found {len(results)} URLs for dork {i}"
                    }
                    if self.file_manager.auto_save_enabled:
                        update_data["saved_count"] = self.file_manager.total_saved

                    progress.update(search_task, **update_data)

                    # Show periodic summary
                    if i % 25 == 0:
                        if self.file_manager.auto_save_enabled:
                            console.print(
                                f"[bold blue]📊 Progress: {i}/{len(dorks)} dorks | {self.search_engine.total_urls_found} URLs | {self.file_manager.total_saved} saved[/bold blue]")
                        else:
                            console.print(
                                f"[bold blue]📊 Progress: {i}/{len(dorks)} dorks | {self.search_engine.total_urls_found} URLs found[/bold blue]")

                except KeyboardInterrupt:
                    console.print(f"\n[yellow]⚠️ Search interrupted by user at dork {i}[/yellow]")
                    break
                except Exception as e:
                    console.print(f"\n[red]❌ Error with dork {i}: {e}[/red]")
                    continue

                progress.advance(search_task)

            # Final flush of auto-save buffer
            if self.file_manager.auto_save_enabled:
                self.file_manager.auto_save_results([], force=True)
                self.file_manager.finalize_auto_save()

    except Exception as e:
        console.print(f"[red]💥 Critical error during search: {e}[/red]")
        if self.file_manager.auto_save_enabled:
            self.file_manager.finalize_auto_save()

    self.stats["end_time"] = datetime.now()
    self.stats["total_results"] = len(all_results)

    # Remove duplicates
    console.print(f"\n[blue]🔄 Processing {len(all_results)} results...[/blue]")
    unique_results = []
    seen_urls = set()

    for result in all_results:
        url = result.get("url", "")
        if url not in seen_urls:
            unique_results.append(result)
            seen_urls.add(url)

    duplicates_removed = len(all_results) - len(unique_results)
    if duplicates_removed > 0:
        console.print(f"[yellow]🔄 Removed {duplicates_removed} duplicate URLs[/yellow]")

    # Final summary
    console.print(f"\n[bold green]🎉 Search Complete![/bold green]")
    console.print(f"[green]• Unique URLs Found: {len(unique_results)}[/green]")
    if self.file_manager.auto_save_enabled:
        console.print(f"[green]• Total URLs Auto-Saved: {self.file_manager.total_saved}[/green]")
    console.print(f"[green]• Dorks Processed: {self.stats['successful_queries']}/{len(dorks)}[/green]")

    return unique_results
class URLVerifier:
    """Simple URL verification"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def verify_url(self, url):
        """Check if URL is accessible"""
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            return {
                "accessible": 200 <= response.status_code < 400,
                "status_code": response.status_code,
                "final_url": str(response.url)
            }
        except Exception as e:
            return {
                "accessible": False,
                "status_code": None,
                "error": str(e)
            }

    def verify_batch(self, results):
        """Verify multiple URLs"""
        console.print("[blue]🔍 Verifying URLs...[/blue]")

        verified_results = []
        accessible_count = 0

        with Progress() as progress:
            task = progress.add_task("Verifying URLs", total=len(results))

            for result in results:
                url_info = self.verify_url(result["url"])
                result.update(url_info)
                verified_results.append(result)

                if url_info.get("accessible", False):
                    accessible_count += 1

                progress.advance(task)
                time.sleep(0.1)  # Small delay to avoid overwhelming servers

        console.print(f"[green]✅ {accessible_count}/{len(results)} URLs are accessible[/green]")
        return verified_results


class SimpleiDork:
    """Main simplified iDork application"""

    def __init__(self):
        self.config = SimpleConfig().config
        self.proxy_manager = None
        self.search_engine = SimpleSearchEngine(self.config)
        self.dork_templates = DorkTemplates()
        self.file_manager = FileManager()
        self.url_verifier = URLVerifier()
        self.results = []
        self.stats = {
            "start_time": None,
            "end_time": None,
            "total_queries": 0,
            "total_results": 0,
            "successful_queries": 0
        }

    def show_welcome(self):
        """Display welcome screen"""
        console.clear()
        console.print(Panel(ASCII_LOGO, border_style="cyan"))
        console.print(Panel(WELCOME_MESSAGE, border_style="green"))

        # Check dependencies
        missing_deps = []
        if not google_search:
            missing_deps.append("googlesearch-python (for Google search)")
        if not TKINTER_AVAILABLE:
            missing_deps.append("tkinter (for file picker)")

        if missing_deps:
            deps_text = "\n".join([f"• {dep}" for dep in missing_deps])
            console.print(Panel(
                f"[yellow]⚠️ Optional dependencies missing:[/yellow]\n{deps_text}\n\n[dim]These features will be limited but the app will still work![/dim]",
                title="[yellow]Optional Dependencies[/yellow]",
                border_style="yellow"
            ))

        input("\n[bold cyan]Press ENTER to continue...[/bold cyan]")

    def choose_search_engine(self):
        """Let user choose search engine"""
        console.print("\n[bold blue]🔍 Choose Search Engine[/bold blue]")

        engines_info = {
            "duckduckgo": ("DuckDuckGo", "✅ Fast & reliable", "🟢"),
            "google": ("Google", "⚠️ Requires extra setup" if not google_search else "✅ Most comprehensive",
                       "🟡" if not google_search else "🟢"),
            "bing": ("Bing", "⚠️ Experimental", "🟡"),
            "yahoo": ("Yahoo", "⚠️ Limited", "🟡"),
            "yandex": ("Yandex", "⚠️ Limited", "🟡")
        }

        table = Table(title="Available Search Engines")
        table.add_column("Engine", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("", style="white", width=3)

        for engine_id, (name, status, icon) in engines_info.items():
            table.add_row(name, status, icon)

        console.print(table)

        choices = list(engines_info.keys())
        engine = Prompt.ask(
            "\nChoose search engine",
            choices=choices,
            default="duckduckgo"
        )

        return engine

    def setup_proxy(self):
        """Setup proxy if user wants"""
        console.print("\n[bold blue]🔒 Proxy Setup (Optional)[/bold blue]")

        use_proxy = Confirm.ask("Do you want to use a proxy?", default=False)
        if not use_proxy:
            return

        proxy_method = Prompt.ask(
            "How do you want to add proxies?",
            choices=["single", "file", "list"],
            default="single"
        )

        proxies = []

        if proxy_method == "single":
            proxy = Prompt.ask("Enter proxy (format: ip:port or http://ip:port)")
            if not proxy.startswith('http'):
                proxy = f"http://{proxy}"
            proxies = [proxy]

        elif proxy_method == "file":
            if TKINTER_AVAILABLE:
                console.print("[cyan]📁 Opening file picker for proxy file...[/cyan]")
                proxy_file = open_file_picker("Select Proxy File", [("Text files", "*.txt"), ("All files", "*.*")])
                if proxy_file:
                    proxies = self._load_proxies_from_file(proxy_file)
            else:
                proxy_file = Prompt.ask("Enter path to proxy file")
                if os.path.exists(proxy_file):
                    proxies = self._load_proxies_from_file(proxy_file)

        elif proxy_method == "list":
            console.print("[yellow]Enter proxies one by one (press ENTER on empty line to finish):[/yellow]")
            while True:
                proxy = input("Proxy: ").strip()
                if not proxy:
                    break
                if not proxy.startswith('http'):
                    proxy = f"http://{proxy}"
                proxies.append(proxy)

        if proxies:
            self.proxy_manager = ProxyManager(proxies)
            self.search_engine = SimpleSearchEngine(self.config, self.proxy_manager)
            console.print(f"[green]✅ Loaded {len(proxies)} proxies[/green]")

    def _load_proxies_from_file(self, filepath):
        """Load proxies from file"""
        proxies = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith('http'):
                            line = f"http://{line}"
                        proxies.append(line)
        except Exception as e:
            console.print(f"[red]❌ Error loading proxies: {e}[/red]")
        return proxies

    def get_dorks(self):
        """Get dorks from user - templates, file, or manual"""
        console.print("\n[bold blue]📝 Get Your Dorks[/bold blue]")

        method = Prompt.ask(
            "How do you want to add dorks?",
            choices=["templates", "file", "manual", "target"],
            default="templates"
        )

        dorks = []

        if method == "templates":
            dorks = self._get_template_dorks()
        elif method == "file":
            dorks = self._get_file_dorks()
        elif method == "manual":
            dorks = self._get_manual_dorks()
        elif method == "target":
            dorks = self._get_target_dorks()

        if dorks:
            console.print(f"[green]✅ Ready to search with {len(dorks)} dorks[/green]")

        return dorks

    def _get_template_dorks(self):
        """Get dorks from templates"""
        console.print("\n[bold cyan]📋 Available Dork Templates[/bold cyan]")

        categories = self.dork_templates.get_categories()

        table = Table()
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="magenta")

        for category in categories:
            dork_count = len(self.dork_templates.get_dorks(category))
            table.add_row(category, str(dork_count))

        console.print(table)

        choice = Prompt.ask(
            "\nChoose template category",
            choices=categories
        )

        # Ask for target site
        target_site = Prompt.ask("Enter target website (optional, press ENTER to skip)", default="").strip()

        dorks = self.dork_templates.get_dorks(choice)

        if target_site:
            dorks = self.dork_templates.format_for_site(dorks, target_site)

        return dorks

    def _get_file_dorks(self):
        """Get dorks from file"""
        if TKINTER_AVAILABLE:
            console.print("[cyan]📁 Opening file picker for dork file...[/cyan]")
            dork_file = open_file_picker("Select Dork File", [("Text files", "*.txt"), ("All files", "*.*")])
            if dork_file:
                return self.file_manager.load_dorks_from_file(dork_file)
        else:
            dork_file = Prompt.ask("Enter path to dork file")
            if os.path.exists(dork_file):
                return self.file_manager.load_dorks_from_file(dork_file)

        console.print("[red]❌ No file selected or file not found[/red]")
        return []

    def _get_manual_dorks(self):
        """Get dorks manually from user"""
        console.print("\n[yellow]Enter your dorks one by one (press ENTER on empty line to finish):[/yellow]")
        dorks = []

        while True:
            dork = input("Dork: ").strip()
            if not dork:
                break
            dorks.append(dork)
            console.print(f"[green]Added: {dork}[/green]")

        return dorks

    def _get_target_dorks(self):
        """Get dorks for specific target"""
        target_site = Prompt.ask("Enter target website (e.g., example.com)")

        console.print("\n[bold cyan]📋 Available Categories for Target[/bold cyan]")
        categories = self.dork_templates.get_categories()

        table = Table()
        table.add_column("Category", style="cyan")
        table.add_column("Description", style="white")

        for category in categories:
            desc = category.replace("🔑", "").replace("📁", "").replace("💾", "").replace("📂", "").replace("⚠️",
                                                                                                        "").replace("🔒",
                                                                                                                    "").replace(
                "🗄️", "").replace("📝", "").strip()
            table.add_row(category, desc)

        console.print(table)

        selection = Prompt.ask(
            "Choose categories (comma-separated) or 'all'",
            default="all"
        )

        all_dorks = []

        if selection.lower() == "all":
            for category in categories:
                category_dorks = self.dork_templates.get_dorks(category)
                all_dorks.extend(self.dork_templates.format_for_site(category_dorks, target_site))
        else:
            selected_categories = [cat.strip() for cat in selection.split(',')]
            for category in categories:
                if any(sel.lower() in category.lower() for sel in selected_categories):
                    category_dorks = self.dork_templates.get_dorks(category)
                    all_dorks.extend(self.dork_templates.format_for_site(category_dorks, target_site))

        return all_dorks

    def configure_search(self):
        """Enhanced search configuration with auto-save options"""
        console.print("\n[bold blue]⚙️ Search Configuration[/bold blue]")

        # Max results per query
        max_results = IntPrompt.ask(
            "Max results per dork",
            default=100,
            show_default=True
        )

        # Verify URLs option
        verify_urls = Confirm.ask("Verify if URLs are accessible? (slower but more accurate)", default=False)

        # Request delay
        delay = Prompt.ask(
            "Delay between requests (seconds)",
            default="8.0"
        )

        try:
            delay = float(delay)
            self.config["request_delay"] = delay
        except ValueError:
            console.print("[yellow]⚠️ Invalid delay, using default 8.0 seconds[/yellow]")

        # AUTO-SAVE CONFIGURATION
        console.print("\n[bold cyan]💾 Auto-Save Configuration[/bold cyan]")
        console.print("[yellow]Auto-save protects your results if the search is interrupted![/yellow]")

        enable_autosave = Confirm.ask("Enable auto-save?", default=True)

        auto_save_settings = {
            "enabled": enable_autosave,
            "formats": [],
            "filename": None,
            "interval": 50
        }

        if enable_autosave:
            # Choose formats
            console.print("\n[cyan]📁 Choose auto-save formats:[/cyan]")

            if Confirm.ask("Save as TXT (human-readable)?", default=True):
                auto_save_settings["formats"].append("txt")

            if Confirm.ask("Save as JSON (structured data)?", default=False):
                auto_save_settings["formats"].append("json")

            if Confirm.ask("Save as CSV (spreadsheet-friendly)?", default=False):
                auto_save_settings["formats"].append("csv")

            if not auto_save_settings["formats"]:
                console.print("[yellow]⚠️ No formats selected, defaulting to TXT[/yellow]")
                auto_save_settings["formats"] = ["txt"]

            # Choose filename
            auto_save_settings["filename"] = Prompt.ask(
                "Auto-save filename prefix",
                default="idork_search"
            )

            # Choose save interval
            auto_save_settings["interval"] = IntPrompt.ask(
                "Save every X results",
                default=50,
                show_default=True
            )

            # Show summary
            formats_str = ", ".join(auto_save_settings["formats"]).upper()
            console.print(f"\n[green]✅ Auto-save enabled:[/green]")
            console.print(f"[green]• Formats: {formats_str}[/green]")
            console.print(f"[green]• Filename: {auto_save_settings['filename']}_autosave_[timestamp][/green]")
            console.print(f"[green]• Interval: Every {auto_save_settings['interval']} results[/green]")

        else:
            console.print("[yellow]⚠️ Auto-save disabled - results only saved at the end[/yellow]")
            console.print("[red]Warning: If search is interrupted, you may lose all progress![/red]")

        return max_results, verify_urls, auto_save_settings

    # REPLACE the run_search method in SimpleiDork class:

    def run_search(self, dorks, engine, max_results):
        """FIXED search function with working auto-save"""
        console.print(f"\n[bold green]🚀 Starting Search[/bold green]")
        console.print(f"[cyan]Engine: {engine.title()}[/cyan]")
        console.print(f"[cyan]Dorks: {len(dorks)}[/cyan]")
        console.print(f"[cyan]Max results per dork: {max_results}[/cyan]")

        # Show auto-save status
        if self.file_manager.auto_save_enabled:
            console.print(f"[green]💾 Auto-save: Every {self.file_manager.auto_save_interval} results[/green]")
        else:
            console.print("[yellow]⚠️ Auto-save disabled[/yellow]")

        # Reset counters
        self.search_engine.total_urls_found = 0

        # Show warning for large searches
        if len(dorks) > 100:
            console.print(f"\n[yellow]⚠️ WARNING: {len(dorks)} dorks will take a long time![/yellow]")
            engine_delay = self.config.get("engine_delays", {}).get(engine, 8.0)
            estimated_time = len(dorks) * engine_delay / 60
            console.print(f"[yellow]Estimated time: {estimated_time:.1f} minutes[/yellow]")

            if self.file_manager.auto_save_enabled:
                console.print(f"[green]✅ Auto-save is enabled - progress will be preserved![/green]")

            if not Confirm.ask("Continue?", default=True):
                console.print("[yellow]Search cancelled by user[/yellow]")
                return []

        self.stats["start_time"] = datetime.now()
        self.stats["total_queries"] = len(dorks)
        all_results = []

        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total})"),
                    TextColumn("[bold green]URLs: {task.fields[urls_found]}[/bold green]"),
                    TextColumn(
                        "[bold blue]Saved: {task.fields[saved_count]}[/bold blue]") if self.file_manager.auto_save_enabled else TextColumn(
                        ""),
                    TimeElapsedColumn(),
                    console=console
            ) as progress:

                task_fields = {"urls_found": 0}
                if self.file_manager.auto_save_enabled:
                    task_fields["saved_count"] = 0

                search_task = progress.add_task(
                    "Searching...",
                    total=len(dorks),
                    **task_fields
                )

                for i, dork in enumerate(dorks, 1):
                    try:
                        # Update progress description
                        dork_preview = dork[:40] + "..." if len(dork) > 40 else dork
                        progress.update(search_task, description=f"Searching: {dork_preview}")

                        # Search with current engine
                        results = self.search_engine.search(dork, engine, max_results)

                        # Add metadata to each result
                        for result in results:
                            result.update({
                                "query": dork,
                                "timestamp": datetime.now().isoformat(),
                                "query_number": i,
                                "dork_index": i
                            })

                        # Add to main results list
                        all_results.extend(results)
                        self.stats["successful_queries"] += 1

                        # *** THIS IS THE KEY FIX ***
                        # Auto-save results immediately if we found any
                        if results and self.file_manager.auto_save_enabled:
                            console.print(f"[cyan]📝 Auto-saving {len(results)} new results...[/cyan]")
                            self.file_manager.auto_save_results(results)
                            console.print(
                                f"[green]✅ Auto-save completed! Buffer now has {len(self.file_manager.results_buffer)} results[/green]")

                        # Update progress with current counts
                        update_data = {
                            "urls_found": self.search_engine.total_urls_found,
                            "description": f"Found {len(results)} URLs for dork {i}"
                        }
                        if self.file_manager.auto_save_enabled:
                            update_data["saved_count"] = self.file_manager.total_saved

                        progress.update(search_task, **update_data)

                        # Show periodic summary with save status
                        if i % 25 == 0:
                            if self.file_manager.auto_save_enabled:
                                console.print(
                                    f"[bold blue]📊 Progress: {i}/{len(dorks)} dorks | {self.search_engine.total_urls_found} URLs | {self.file_manager.total_saved} saved to file[/bold blue]")
                            else:
                                console.print(
                                    f"[bold blue]📊 Progress: {i}/{len(dorks)} dorks | {self.search_engine.total_urls_found} URLs found[/bold blue]")

                    except KeyboardInterrupt:
                        console.print(f"\n[yellow]⚠️ Search interrupted by user at dork {i}[/yellow]")
                        console.print(f"[cyan]💾 Forcing final auto-save...[/cyan]")
                        if self.file_manager.auto_save_enabled:
                            self.file_manager.auto_save_results([], force=True)
                            self.file_manager.finalize_auto_save()
                        break
                    except Exception as e:
                        console.print(f"\n[red]❌ Error with dork {i}: {e}[/red]")
                        continue

                    progress.advance(search_task)

                # Final flush of auto-save buffer
                if self.file_manager.auto_save_enabled:
                    console.print(f"[cyan]💾 Final auto-save flush...[/cyan]")
                    self.file_manager.auto_save_results([], force=True)
                    self.file_manager.finalize_auto_save()

        except Exception as e:
            console.print(f"[red]💥 Critical error during search: {e}[/red]")
            # Emergency save
            if self.file_manager.auto_save_enabled:
                console.print(f"[yellow]🚨 Emergency auto-save...[/yellow]")
                self.file_manager.finalize_auto_save()

        self.stats["end_time"] = datetime.now()
        self.stats["total_results"] = len(all_results)

        # Remove duplicates
        console.print(f"\n[blue]🔄 Processing {len(all_results)} results...[/blue]")
        unique_results = []
        seen_urls = set()

        for result in all_results:
            url = result.get("url", "")
            if url not in seen_urls:
                unique_results.append(result)
                seen_urls.add(url)

        duplicates_removed = len(all_results) - len(unique_results)
        if duplicates_removed > 0:
            console.print(f"[yellow]🔄 Removed {duplicates_removed} duplicate URLs[/yellow]")

        # Final summary
        console.print(f"\n[bold green]🎉 Search Complete![/bold green]")
        console.print(f"[green]• Unique URLs Found: {len(unique_results)}[/green]")
        if self.file_manager.auto_save_enabled:
            console.print(f"[green]• Total URLs Auto-Saved: {self.file_manager.total_saved}[/green]")

            # Show auto-save file locations
            console.print(f"\n[bold cyan]📁 Auto-save files created:[/bold cyan]")
            for format_type, filepath in self.file_manager.auto_save_files.items():
                if filepath:
                    console.print(f"[cyan]• {format_type.upper()}: {filepath}[/cyan]")

        console.print(f"[green]• Dorks Processed: {self.stats['successful_queries']}/{len(dorks)}[/green]")

        return unique_results


    def show_results_preview(self, results):
        """Show a preview of results"""
        if not results:
            console.print("[yellow]⚠️ No results found[/yellow]")
            return

        console.print(f"\n[bold green]🎉 Found {len(results)} unique results![/bold green]")

        # Show statistics
        duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()

        stats_table = Table(title="Search Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")

        stats_table.add_row("Total Queries", str(self.stats["total_queries"]))
        stats_table.add_row("Successful Queries", str(self.stats["successful_queries"]))
        stats_table.add_row("Total Results", str(self.stats["total_results"]))
        stats_table.add_row("Unique Results", str(len(results)))
        stats_table.add_row("Duration", f"{duration:.1f} seconds")

        if self.stats["total_queries"] > 0:
            avg_results = len(results) / self.stats["total_queries"]
            stats_table.add_row("Avg Results/Query", f"{avg_results:.1f}")

        console.print(stats_table)

        # Show sample results
        console.print(f"\n[bold cyan]📋 Sample Results (showing first 10):[/bold cyan]")

        sample_table = Table()
        sample_table.add_column("No.", style="dim", width=4)
        sample_table.add_column("Title", style="cyan", max_width=50)
        sample_table.add_column("URL", style="blue", max_width=60)
        sample_table.add_column("Engine", style="green", width=10)

        for i, result in enumerate(results[:10], 1):
            title = result.get("title", "N/A")[:47] + "..." if len(result.get("title", "")) > 50 else result.get(
                "title", "N/A")
            url = result.get("url", "N/A")[:57] + "..." if len(result.get("url", "")) > 60 else result.get("url", "N/A")
            engine = result.get("engine", "unknown").upper()

            sample_table.add_row(str(i), title, url, engine)

        console.print(sample_table)

        if len(results) > 10:
            console.print(f"[dim]... and {len(results) - 10} more results[/dim]")

    def save_results_interactive(self, results):
        """Interactive save results"""
        if not results:
            return

        console.print("\n[bold blue]💾 Save Results[/bold blue]")

        save_results = Confirm.ask("Do you want to save the results?", default=True)
        if not save_results:
            return

        # Choose format
        format_choice = Prompt.ask(
            "Choose output format",
            choices=["txt", "json", "csv"],
            default="txt"
        )

        # Choose filename
        if TKINTER_AVAILABLE and Confirm.ask("Use file picker for save location?", default=True):
            console.print("[cyan]📁 Opening save dialog...[/cyan]")

            filetypes = [
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]

            filename = save_file_picker(
                "Save Results As",
                f".{format_choice}",
                filetypes
            )

            if filename:
                # Extract directory and filename
                filepath = Path(filename)
                self.file_manager.output_dir = filepath.parent
                filename_only = filepath.stem

                saved_path = self.file_manager.save_results(results, filename_only, format_choice)
                if saved_path:
                    console.print(f"[green]✅ Results saved successfully![/green]")
        else:
            # Manual filename entry
            filename = Prompt.ask(
                "Enter filename (without extension)",
                default=f"idork_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )

            saved_path = self.file_manager.save_results(results, filename, format_choice)
            if saved_path:
                console.print(f"[green]✅ Results saved to: {saved_path}[/green]")

    def main_menu(self):
        """Enhanced main application flow with integrated auto-save"""
        while True:
            try:
                # Step 1: Welcome
                self.show_welcome()

                # Step 2: Choose search engine
                engine = self.choose_search_engine()

                # Step 3: Setup proxy (optional)
                self.setup_proxy()

                # Step 4: Get dorks
                dorks = self.get_dorks()
                if not dorks:
                    console.print("[red]❌ No dorks provided. Exiting.[/red]")
                    break

                # Step 5: Configure search (now includes auto-save)
                max_results, verify_urls, auto_save_settings = self.configure_search()

                # Step 6: Setup auto-save if enabled
                if auto_save_settings["enabled"]:
                    self.file_manager.auto_save_interval = auto_save_settings["interval"]
                    self.file_manager.setup_auto_save(
                        auto_save_settings["filename"],
                        auto_save_settings["formats"]
                    )
                else:
                    self.file_manager.auto_save_enabled = False

                # Step 7: Run search
                results = self.run_search(dorks, engine, max_results)

                # Step 8: Verify URLs if requested
                if verify_urls and results:
                    console.print("\n[blue]🔍 Verifying URLs...[/blue]")
                    results = self.url_verifier.verify_batch(results)

                    # Filter out inaccessible URLs if user wants
                    accessible_only = Confirm.ask("Show only accessible URLs?", default=False)
                    if accessible_only:
                        accessible_results = [r for r in results if r.get("accessible", True)]
                        console.print(f"[cyan]Filtered to {len(accessible_results)} accessible URLs[/cyan]")
                        results = accessible_results

                # Step 9: Show results
                self.show_results_preview(results)

                # Step 10: Save final results (separate from auto-save)
                self.save_final_results_interactive(results, auto_save_settings)

                # Step 11: Ask to continue
                console.print("\n[bold green]🎉 Search Complete![/bold green]")

                if not Confirm.ask("Do you want to run another search?", default=False):
                    break

                # Reset for next search
                self.results = []
                self.stats = {
                    "start_time": None,
                    "end_time": None,
                    "total_queries": 0,
                    "total_results": 0,
                    "successful_queries": 0
                }

            except KeyboardInterrupt:
                console.print("\n\n[yellow]👋 Thanks for using iDork! Goodbye![/yellow]")
                break
            except Exception as e:
                console.print(f"\n[red]❌ Unexpected error: {e}[/red]")
                if Confirm.ask("Do you want to continue?", default=True):
                    continue
                else:
                    break

    def save_final_results_interactive(self, results, auto_save_settings):
        """Enhanced save results with auto-save awareness"""
        if not results:
            return

        console.print("\n[bold blue]💾 Final Results Save[/bold blue]")

        if auto_save_settings["enabled"]:
            console.print(f"[green]✅ Your results are already auto-saved![/green]")
            console.print(f"[cyan]Auto-saved files contain {self.file_manager.total_saved} results[/cyan]")

            save_additional = Confirm.ask("Save additional final copy?", default=False)
            if not save_additional:
                console.print("[cyan]📁 Results are safely stored in auto-save files[/cyan]")
                return
        else:
            save_results = Confirm.ask("Do you want to save the results?", default=True)
            if not save_results:
                return

        # Choose format for final save
        format_choice = Prompt.ask(
            "Choose final save format",
            choices=["txt", "json", "csv"],
            default="txt"
        )

        # Choose filename
        if TKINTER_AVAILABLE and Confirm.ask("Use file picker for save location?", default=True):
            console.print("[cyan]📁 Opening save dialog...[/cyan]")

            filetypes = [
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]

            filename = save_file_picker(
                "Save Final Results As",
                f".{format_choice}",
                filetypes
            )

            if filename:
                filepath = Path(filename)
                self.file_manager.output_dir = filepath.parent
                filename_only = filepath.stem

                saved_path = self.file_manager.save_results(results, filename_only, format_choice)
                if saved_path:
                    console.print(f"[green]✅ Final results saved successfully![/green]")
        else:
            # Manual filename entry
            default_name = "idork_final_results" if not auto_save_settings[
                "enabled"] else f"{auto_save_settings['filename']}_final"
            filename = Prompt.ask(
                "Enter final filename (without extension)",
                default=f"{default_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )

            saved_path = self.file_manager.save_results(results, filename, format_choice)
            if saved_path:
                console.print(f"[green]✅ Final results saved to: {saved_path}[/green]")


def show_installation_help():
    """Show installation help for missing dependencies"""
    console.print("\n[bold red]📦 Missing Dependencies[/bold red]")

    help_text = """
[bold yellow]Required Dependencies:[/bold yellow]
pip install rich duckduckgo-search requests

[bold yellow]Optional Dependencies:[/bold yellow]
pip install googlesearch-python  # For Google search support
pip install tk                   # For file picker (usually pre-installed)

[bold cyan]Installation Steps:[/bold cyan]
1. Open Command Prompt/Terminal
2. Run: pip install rich duckduckgo-search requests
3. For Google search: pip install googlesearch-python
4. Restart this application

[bold green]Note:[/bold green] The app will work with just the required dependencies!
Google search and file picker are optional features.
"""

    console.print(Panel(help_text, border_style="yellow"))


def check_dependencies():
    """Check if all required dependencies are available"""
    missing_required = []

    # Check required dependencies
    try:
        import rich
    except ImportError:
        missing_required.append("rich")

    try:
        import requests
    except ImportError:
        missing_required.append("requests")

    try:
        from duckduckgo_search import DDGS
    except ImportError:
        missing_required.append("duckduckgo-search")

    if missing_required:
        console.print(f"[bold red]❌ Missing required dependencies: {', '.join(missing_required)}[/bold red]")
        show_installation_help()
        return False

    return True


def main():
    """Main entry point - no arguments needed!"""
    console.print("[bold cyan]🚀 Starting iDork v2.0...[/bold cyan]")

    # Check dependencies
    if not check_dependencies():
        console.print("\n[red]❌ Cannot start without required dependencies[/red]")
        input("Press ENTER to exit...")
        return

    # Show startup info
    console.print("[green]✅ All required dependencies found![/green]")

    # Optional dependency warnings
    warnings = []
    if not google_search:
        warnings.append("Google search will be limited (install googlesearch-python for full support)")
    if not TKINTER_AVAILABLE:
        warnings.append("File picker not available (install tkinter if needed)")

    if warnings:
        console.print("\n[yellow]⚠️ Optional features:[/yellow]")
        for warning in warnings:
            console.print(f"[dim]• {warning}[/dim]")

    try:
        # Initialize and run the app
        app = SimpleiDork()
        app.main_menu()

    except KeyboardInterrupt:
        console.print("\n\n[yellow]👋 Goodbye![/yellow]")
    except Exception as e:
        console.print(f"\n[red]💥 Critical error: {e}[/red]")
        console.print("[dim]Please report this error to the developer[/dim]")
        input("Press ENTER to exit...")


def show_help():
    """Show help information"""
    help_text = """
[bold cyan]iDork v2.0 - User Friendly Interactive Mode[/bold cyan]

[bold yellow]How to use:[/bold yellow]
1. Just run: python idork.py
2. Follow the interactive prompts
3. No complex commands needed!

[bold yellow]Features:[/bold yellow]
• 🔍 Multiple search engines
• 📁 Easy file picker
• 📝 Pre-made dork templates  
• 🔒 Optional proxy support
• 💾 Multiple output formats
• ✅ URL verification
• 📊 Detailed statistics

[bold yellow]File Formats Supported:[/bold yellow]
• Input: .txt files with dorks (one per line)
• Output: .txt, .json, .csv formats

[bold yellow]Example dork file:[/bold yellow]
site:example.com login
inurl:admin
filetype:pdf confidential
"index of" password

[bold green]Just run the program and follow the prompts! 🚀[/bold green]
"""

    console.print(Panel(help_text, border_style="green"))


if __name__ == "__main__":
    # Check if user needs help
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help', 'help']:
            show_help()
            sys.exit(0)
        elif sys.argv[1] in ['-v', '--version', 'version']:
            console.print("[bold cyan]iDork v2.0 - Interactive Edition[/bold cyan]")
            console.print("[green]Developer: root (@rootbck)[/green]")
            sys.exit(0)
        else:
            console.print("[yellow]⚠️ This version is fully interactive - no arguments needed![/yellow]")
            console.print("[cyan]Just run: python idork.py[/cyan]")
            console.print("[dim]Use 'python idork.py help' for more information[/dim]")

    # Run the main application
    main()


# Additional utility functions for advanced users
def quick_search(dork, engine="duckduckgo", max_results=50):
    """Quick search function for advanced users who want to import this module"""
    config = SimpleConfig().config
    search_engine = SimpleSearchEngine(config)
    results = search_engine.search(dork, engine, max_results)
    return results


def batch_search(dorks, engine="duckduckgo", max_results=50):
    """Batch search function for advanced users"""
    config = SimpleConfig().config
    search_engine = SimpleSearchEngine(config)
    all_results = []

    for dork in dorks:
        try:
            results = search_engine.search(dork, engine, max_results)
            all_results.extend(results)
            time.sleep(config["request_delay"])
        except Exception as e:
            print(f"Error with dork '{dork}': {e}")

    return all_results


# Export key classes for advanced users who want to import
__all__ = [
    'SimpleiDork',
    'SimpleSearchEngine',
    'DorkTemplates',
    'FileManager',
    'URLVerifier',
    'quick_search',
    'batch_search'
]