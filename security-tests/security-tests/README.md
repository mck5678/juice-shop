# Automated Security Testing

My university assignment for DevSecOps involved analyzing OWASP Juice Shop using STRIDE threat modeling, identifying potential security threats theoretically. It made me curious to see how actual vulnerability testing is done in security work, so I built these automated test scripts in Python.

## What It Does

Automatically tests for vulnerabilities I wrote about:
- **SQL Injection** - Login bypass
- **XSS** - Reflected XSS in search
- **Access Control** - Exposed admin files

## How to Run
```bash
# Start Juice Shop first
npm start

# Run all tests
./run_tests.sh
```

**Requirements**: Python 3, `pip install requests`

## Results

- SQL Injection: 1 CRITICAL vulnerability found
- XSS: Secure
- Access Control: 3 MEDIUM vulnerabilities found

JSON reports generated for each test.

## Why

Turned my theoretical security analysis into working code to understand how security testing actually works in real jobs.
