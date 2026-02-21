"""
DNS Monitor - Capture API host from game network traffic
No injection needed! Just monitors DNS lookups while the game runs.

Usage:
1. Run this script BEFORE opening the game
2. Open the game (Global/SEA version)
3. Navigate to any player profile
4. The script will capture all DNS lookups containing 'netease' or 'ms-prod'
"""
import subprocess
import time
import re
import sys

OUTPUT_FILE = r"C:\Users\AD\Desktop\find api\dns_capture.txt"

def get_dns_cache():
    """Get current DNS resolver cache entries"""
    try:
        result = subprocess.run(
            ['ipconfig', '/displaydns'],
            capture_output=True, text=True, encoding='utf-8', errors='replace'
        )
        return result.stdout
    except:
        return ""

def parse_dns_entries(text):
    """Parse DNS cache entries, return set of (hostname, ip) tuples"""
    entries = set()
    current_host = None
    for line in text.split('\n'):
        line = line.strip()
        if 'Record Name' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                current_host = parts[1].strip()
        elif ('A (Host) Record' in line or 'AAAA' in line) and current_host:
            parts = line.split(':', 1)
            if len(parts) == 2:
                ip = parts[1].strip()
                entries.add((current_host, ip))
    return entries

def is_interesting(hostname):
    """Check if hostname is game-related"""
    keywords = ['netease', 'ms-prod', 'ms-', 'nie.', 'wwm', 'yysls', 'flk', 
                'game', 'sea', 'oversea', 'global', 'prod', 'uwsgi']
    hostname_lower = hostname.lower()
    return any(kw in hostname_lower for kw in keywords)

def main():
    print("=" * 50)
    print("  DNS MONITOR - Game API Host Capture")
    print("=" * 50)
    print()
    print("Instructions:")
    print("  1. Keep this script running")
    print("  2. Open the Global/SEA game")
    print("  3. Open any player profile")
    print("  4. Check this console for captured hosts")
    print()
    
    # Clear DNS cache first
    print("[*] Flushing DNS cache...")
    subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
    print("[+] DNS cache cleared")
    
    # Get baseline
    print("[*] Getting baseline DNS entries...")
    baseline = parse_dns_entries(get_dns_cache())
    print(f"[*] Baseline: {len(baseline)} entries")
    
    print("\n[*] Monitoring DNS... (Ctrl+C to stop)\n")
    
    all_new = set()
    game_hosts = set()
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"DNS Monitor started at {time.strftime('%H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
    
    try:
        while True:
            current = parse_dns_entries(get_dns_cache())
            new_entries = current - baseline - all_new
            
            if new_entries:
                all_new.update(new_entries)
                
                for host, ip in sorted(new_entries):
                    interesting = is_interesting(host)
                    marker = " <<<< GAME HOST!" if interesting else ""
                    line = f"  {host} -> {ip}{marker}"
                    
                    if interesting:
                        game_hosts.add((host, ip))
                        print(f"\033[92m[!!!] {host} -> {ip} <<<< POSSIBLE API HOST\033[0m")
                        
                        with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"[{time.strftime('%H:%M:%S')}] GAME: {host} -> {ip}\n")
                    else:
                        # Print non-game hosts quietly
                        pass
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        pass
    
    print("\n" + "=" * 50)
    print("  RESULTS")
    print("=" * 50)
    
    print(f"\nTotal new DNS entries: {len(all_new)}")
    print(f"Game-related hosts: {len(game_hosts)}")
    
    if game_hosts:
        print("\n>>> GAME HOSTS FOUND:")
        for host, ip in sorted(game_hosts):
            print(f"  {host} -> {ip}")
    else:
        print("\nNo game-related hosts detected.")
        print("Showing ALL new DNS entries:")
        for host, ip in sorted(all_new):
            print(f"  {host} -> {ip}")
    
    # Save full results
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        f.write(f"\n\nFull results at {time.strftime('%H:%M:%S')}:\n")
        f.write("=" * 50 + "\n")
        f.write(f"\nGame hosts ({len(game_hosts)}):\n")
        for host, ip in sorted(game_hosts):
            f.write(f"  {host} -> {ip}\n")
        f.write(f"\nAll new entries ({len(all_new)}):\n")
        for host, ip in sorted(all_new):
            f.write(f"  {host} -> {ip}\n")
    
    print(f"\nResults saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
