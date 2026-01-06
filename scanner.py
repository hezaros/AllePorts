#!/usr/bin/env python3
# Smart Port Scanner - Developed with Antigravity
import argparse
import subprocess
import sys
import shutil
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

console = Console()

class SmartScanner:
    def __init__(self, target, mode="default", no_udp=False):
        self.target = target
        self.mode = mode
        self.no_udp = no_udp
        self.results = {} # Key: (port, protocol), Value: port_info dict
        self.nmap_path = shutil.which("nmap")
        
        if not self.nmap_path:
            console.print("[bold red]Error:[/bold red] nmap is not installed or not in PATH.")
            sys.exit(1)
            
        if os.geteuid() != 0:
            console.print("[bold yellow]Warning:[/bold yellow] You are not running as root. Some scans (like SYN scan or UDP scan) may fail or fall back to connect scan.")

    def scan(self):
        console.print(f"[bold blue]Starting scan on {self.target} in {self.mode} mode...[/bold blue]")
        
        if self.mode == "fast":
            self._scan_fast()
        elif self.mode == "slow":
            self._scan_slow()
        else:
            self._scan_default()

        # Smart Retry Logic for filtered ports
        # Identify ports that are currently filtered
        filtered = [p for k, p in self.results.items() if p['state'] in ['filtered', 'open|filtered']]
        
        if filtered:
             self._retry_smart(filtered)
        
        self._print_report()

    def _retry_smart(self, filtered_ports):
        """Attempts to re-scan filtered ports with different flags."""
        console.print(f"\n[bold yellow]Smart Retry:[/bold yellow] Attempting to unmask {len(filtered_ports)} filtered ports...")
        
        # Extract ports
        ports = [p['port'] for p in filtered_ports]
        if not ports:
            return
            
        # Nmap accepts comma separated ports, but too many might break command line length?
        # Nmap can handle reasonably long lists. If > 500, maybe chunk it.
        # For simplicity, let's take max 100 filtered ports to retry to avoid hanging forever.
        
        ports_to_retry = ports[:100]
        port_arg = ",".join(ports_to_retry)
        
        if len(ports) > 100:
            console.print(f"[dim]Too many filtered ports. Retrying top 100: {port_arg}[/dim]")
        
        # Strategy 1: ACK Scan (-sA) - Good for mapping firewall rulesets
        self._run_nmap(["-sA", "-p", port_arg, "-Pn"], "ACK Scan (Firewall mapping)")
        
        # Strategy 2: Window Scan (-sW) - Can reveal open ports on some systems
        self._run_nmap(["-sW", "-p", port_arg, "-Pn"], "Window Scan")
        
        # Strategy 3: FIN Scan (-sF)
        self._run_nmap(["-sF", "-p", port_arg, "-Pn"], "FIN Scan")
        
        # Strategy 4: Xmas Scan (-sX) - FIN, PSH, URG
        self._run_nmap(["-sX", "-p", port_arg, "-Pn"], "Xmas Scan (FIN/PSH/URG)")
        
        # Strategy 5: Maimon Scan (-sM) - FIN, ACK
        self._run_nmap(["-sM", "-p", port_arg, "-Pn"], "Maimon Scan (FIN/ACK)")
        
        # Strategy 6: Null Scan (-sN) - No flags
        self._run_nmap(["-sN", "-p", port_arg, "-Pn"], "Null Scan (No Flags)")

    def _run_nmap(self, args, description):
        """Runs nmap with provided args and returns parsed XML root or None."""
        # Create a temp file for XML output
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.xml') as tmp_xml:
            tmp_xml_path = tmp_xml.name
            
            
        # Add basic flags: output to XML file, stats every 1s
        cmd = [self.nmap_path, "-oX", tmp_xml_path, "--stats-every", "1s"] + args + [self.target]
        
        # Enhanced Description with Flags
        flags_str = " ".join(args)
        full_desc = f"{description} [dim green]({flags_str})[/dim green]"
        
        # Setup Rich Progress Bar (Matrix Style)
        with Progress(
            SpinnerColumn(style="bold green"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=None, style="green", complete_style="bold green", finished_style="bold green"),
            TextColumn("[bold green]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            transient=True 
        ) as progress:
            task_id = progress.add_task(full_desc, total=100)
            
            try:
                # Merge stdout and stderr to capture stats
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT, 
                    universal_newlines=True,
                    bufsize=1
                )
                
                # Check for 100% manually to ensure bar completes
                completed = False
                
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        # Regex to parse Nmap stats: "About 5.00% done; ETC: 12:00 (0:00:45 remaining)"
                        # Example: "SYN Stealth Scan Timing: About 1.50% done; ETC: 12:16 (0:01:06 remaining)"
                        match = re.search(r"About\s+(\d+\.\d+)%\s+done", output)
                        if match:
                            percent = float(match.group(1))
                            progress.update(task_id, completed=percent)
                            if percent >= 99.9:
                                completed = True
                                
                process.wait()
                if not completed and process.returncode == 0:
                     progress.update(task_id, completed=100)

            except FileNotFoundError:
                 console.print("[bold red]Error:[/bold red] Nmap binary not found during execution.")
                 return None
            except Exception as e:
                console.print(f"[bold red]Unexpected error:[/bold red] {e}")
                return None
        
        # Check return code
        if process.returncode != 0:
            # We already consumed stdout/stderr, so we can't easily print it unless we stored it.
            # But usually if nmap fails, it prints something before exiting.
            console.print(f"[dim green]Nmap process finished with exit code {process.returncode}[/dim green]")

        # Read and parse XML
        try:
            with open(tmp_xml_path, 'r') as f:
                xml_content = f.read()
            return self._parse_xml(xml_content)
        except Exception as e:
            console.print(f"[bold red]Error reading scan results:[/bold red] {e}")
            return None
        finally:
            if os.path.exists(tmp_xml_path):
                os.remove(tmp_xml_path)

    def _parse_xml(self, xml_content):
        if not xml_content: return None
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                ports_elem = host.find("ports")
                if ports_elem:
                    for port_elem in ports_elem.findall("port"):
                        port_id = port_elem.get("portid")
                        protocol = port_elem.get("protocol")
                        state_elem = port_elem.find("state")
                        state = state_elem.get("state") if state_elem is not None else "unknown"
                        reason = state_elem.get("reason") if state_elem is not None else ""
                        
                        service_elem = port_elem.find("service")
                        service = service_elem.get("name") if service_elem is not None else "unknown"
                        
                        port_info = {
                            "port": port_id, 
                            "protocol": protocol, 
                            "state": state, 
                            "service": service,
                            "reason": reason
                        }
                        
                        key = (port_id, protocol)
                        
                        # Priority: open > closed > unfiltered > filtered
                        priority_map = {
                            "open": 4,
                            "closed": 3,
                            "unfiltered": 2,
                            "open|filtered": 1,
                            "filtered": 0
                        }
                        
                        existing = self.results.get(key)
                        new_priority = priority_map.get(state, 0)
                        old_priority = priority_map.get(existing['state'], 0) if existing else -1
                        
                        if new_priority > old_priority:
                            self.results[key] = port_info
                        elif new_priority == old_priority and "reason" in port_info and port_info['reason']:
                             # Update detail if same state but potentially better reason
                             self.results[key] = port_info

            return root
        except ET.ParseError:
            console.print("[bold red]Error parsing Nmap XML output[/bold red]")
            return None

    def _scan_fast(self):
        # Fast: Top 100 TCP & UDP
        # Command: nmap -F -sS -sU -sV <target>
        
        flags = ["-F", "-sV"]
        desc = "Fast Scan"
        
        # Check permissions and user preference for UDP
        use_udp = (os.geteuid() == 0) and (not self.no_udp)
        
        if os.geteuid() == 0:
            flags.append("-sS")
            if use_udp:
                flags.append("-sU")
                desc = "Fast Scan (TCP/UDP)"
            else:
                 console.print("[dim green]Skipping UDP (requested or non-root)[/dim green]")
        else:
            flags.append("-sT") # Connect scan
            console.print("[dim green]Non-root: Skipping UDP and using Connect Scan (-sT)[/dim green]")
            
        self._run_nmap(flags, desc)

    def _scan_default(self):
        # Default: TCP All, UDP Top 20
        
        # 1. TCP All
        console.print("[bold green]Step 1/2: Scanning all TCP ports...[/bold green]")
        tcp_flags = ["-p-", "-sV", "-T4"]
        if os.geteuid() == 0:
            tcp_flags.append("-sS")
        else:
            tcp_flags.append("-sT")
            
        self._run_nmap(tcp_flags, "TCP All-Port Scan")
        
        # 2. UDP Top 20
        use_udp = (os.geteuid() == 0) and (not self.no_udp)
        
        if use_udp:
            console.print("[bold green]Step 2/2: Scanning top 20 UDP ports...[/bold green]")
            self._run_nmap(["-sU", "--top-ports", "20", "-sV"], "UDP Top 20 Scan")
        else:
             if self.no_udp:
                console.print("[dim green]Skipping UDP scan (--no-udp specified)[/dim green]")
             else:
                console.print("[dim green]Skipping UDP scan (requires root)[/dim green]")

    def _scan_slow(self):
        # Slow: TCP All, UDP All
        
        # 1. TCP All
        console.print("[bold green]Step 1/2: Scanning all TCP ports...[/bold green]")
        tcp_flags = ["-p-", "-sV", "-T4"]
        if os.geteuid() == 0:
            tcp_flags.append("-sS")
        else:
            tcp_flags.append("-sT")

        self._run_nmap(tcp_flags, "TCP All-Port Scan")
        
        # 2. UDP All
        use_udp = (os.geteuid() == 0) and (not self.no_udp)
        
        if use_udp:
            console.print("[bold green]Step 2/2: Scanning all UDP ports (This will take a long time)...[/bold green]")
            self._run_nmap(["-sU", "-p-", "-sV", "-T4"], "UDP All-Port Scan")
        else:
            if self.no_udp:
                console.print("[dim green]Skipping UDP scan (--no-udp specified)[/dim green]")
            else:
                console.print("[dim green]Skipping UDP scan (requires root)[/dim green]")

    def _print_report(self):
        console.print("\n")
        # Matrix Style: No header borders, minimal lines, Green text.
        table = Table(
            title=f"Target: {self.target}", 
            show_header=True, 
            header_style="bold black on green",
            box=box.SIMPLE, # Minimal box
            border_style="green",
            title_style="bold green"
        )
        table.add_column("PORT", justify="right", style="bold green")
        table.add_column("PROTO", style="green")
        table.add_column("STATE", justify="center")
        table.add_column("SERVICE", style="green")
        table.add_column("VERSION/REASON", style="dim green")

        # Sort by port number
        sorted_ports = sorted(self.results.values(), key=lambda x: int(x['port']))

        if not sorted_ports:
            console.print("[green]No interesting ports found.[/green]")
            return

        for p in sorted_ports:
            state = p['state']
            if "open" in state and "filtered" not in state:
                state_fmt = f"[bold green]{state.upper()}[/bold green]"
            elif "filtered" in state:
                state_fmt = f"[bold yellow]{state.upper()}[/bold yellow]"
            elif "closed" in state:
                state_fmt = f"[bold red]{state.upper()}[/bold red]"
            elif "unfiltered" in state:
                state_fmt = f"[bold white]{state.upper()}[/bold white]"
            else:
                state_fmt = f"[green]{state}[/green]"

            table.add_row(p['port'], p['protocol'], state_fmt, p['service'], p.get('reason', ''))

        console.print(table)
        
        # Summary stats
        open_count = sum(1 for p in self.results.values() if 'open' in p['state'] and 'filtered' not in p['state'])
        filtered_count = sum(1 for p in self.results.values() if 'filtered' in p['state'])
        closed_count = sum(1 for p in self.results.values() if 'closed' in p['state'])
        
        console.print(f"\n[green]System Analysis:[/green] [bold green]{open_count} UNLOCKED[/bold green] | [bold red]{closed_count} LOCKED[/bold red] | [bold yellow]{filtered_count} HIDDEN[/bold yellow]")

def main():
    parser = argparse.ArgumentParser(description="Smart Port Scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--mode", choices=["fast", "default", "slow"], default="default", help="Scan mode")
    parser.add_argument("--no-udp", action="store_true", help="Disable UDP scanning completely")
    
    # Allow passing through nmap args? For now, keep it simple as per request.
    
    args = parser.parse_args()

    scanner = SmartScanner(args.target, args.mode, args.no_udp)
    scanner.scan()

if __name__ == "__main__":
    main()
