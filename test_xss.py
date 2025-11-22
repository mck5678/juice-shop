#!/usr/bin/env python3

import requests
import json
from datetime import datetime

TARGET_URL = "http://localhost:3000"
REPORT_FILE = "xss_results.json"

def test_search_xss():
    print("\n[*] Testing Reflected XSS in search...")
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>"
    ]
    
    results = []
    
    for payload in payloads:
        print(f"[*] Trying payload: {payload}")
        
        try:
            response = requests.get(
                f"{TARGET_URL}/rest/products/search",
                params={"q": payload},
                timeout=10
            )
            
            if payload in response.text and '&lt;' not in response.text:
                print(f"[!] VULNERABLE! XSS payload reflected: {payload}")
                results.append({
                    "vulnerability": "Reflected XSS - Search Function",
                    "payload": payload,
                    "status": "VULNERABLE",
                    "severity": "HIGH"
                })
                return results
                
        except Exception as e:
            print(f"[!] Error: {e}")
    
    if not results:
        print("[+] Search appears secure against XSS")
        results.append({
            "vulnerability": "Reflected XSS",
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
    print("XSS Security Test")
    print(f"Target: {TARGET_URL}")
    print("="*60)
    
    try:
        response = requests.get(TARGET_URL, timeout=5)
        print("[+] Target is reachable")
    except:
        print("[!] Cannot connect to Juice Shop")
        return
    
    results = test_search_xss()
    generate_report(results)
    
    print("\n" + "="*60)
    vulnerable = sum(1 for r in results if r.get('status') == 'VULNERABLE')
    print(f"Vulnerabilities Found: {vulnerable}")
    print("="*60)

if __name__ == "__main__":
    main()