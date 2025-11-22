#!/bin/bash

echo "=========================================="
echo "OWASP Juice Shop Security Tests"
echo "=========================================="
echo ""

echo "[*] Running SQL Injection tests..."
python3 test_sql_injection.py

echo ""
echo "[*] Running XSS tests..."
python3 test_xss.py

echo ""
echo "[*] Running Access Control tests..."
python3 test_access_control.py

echo ""
echo "=========================================="
echo "All tests complete!"
echo "Check the JSON files for detailed results"
echo "=========================================="