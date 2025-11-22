#!/usr/bin/env python3

import requests
import json
from datetime import datetime

TARGET_URL = "http://localhost:3000"
REPORT_FILE = "access_control_results.json"

def test_admin_endpoints():
    print("\n[*] Testing for exposed administrative endpoints...")
    
    results = []
    admin_paths = [
        "/ftp",
        "/ftp/legal.md",
        "/ftp/package.json",
        "/rest/admin/application-version"
    ]
    
    for path in admin_paths:
        print(f"[*] Checking: {path}")
        
        try:
            response = requests.get(
                f"{TARGET_URL}{path}",
                timeout=10
            )
            
            if response.status_code == 200 and len(response.content) > 0:
                print(f"[!] VULNERABLE! Exposed endpoint: {path}")
                results.append({
                    "vulnerability": "Information Disclosure - Exposed Files",
                    "endpoint": path,
                    "status": "VULNERABLE",
                    "severity": "MEDIUM"
                })
                
        except Exception as e:
            print(f"[!] Error: {e}")
    
    if not results:
        print("[+] No exposed endpoints found")
        results.append({
            "vulnerability": "Information Disclosure",
            "status": "SECURE"
        })
    
    return results

def generate_report(results):
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": TARGET_URL,
        "findings": results
    }
    
    with open(REPORT_FILE, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[*] Report saved to: {REPORT_FILE}")

def main():
    print("="*60)
    print("Access Control Security Test")
    print(f"Target: {TARGET_URL}")
    print("="*60)
    
    try:
        response = requests.get(TARGET_URL, timeout=5)
        print("[+] Target is reachable")
    except:
        print("[!] Cannot connect to Juice Shop")
        return
    
    results = test_admin_endpoints()
    generate_report(results)
    
    print("\n" + "="*60)
    vulnerable = sum(1 for r in results if r.get('status') == 'VULNERABLE')
    print(f"Vulnerabilities Found: {vulnerable}")
    print("="*60)

if __name__ == "__main__":
    main()