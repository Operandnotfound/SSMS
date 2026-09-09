"""
SecureMailScope - Build and Verification Entrypoint
Verifies directory structure, dependencies, module imports, and executes the test suite.
"""

import os
import sys
import unittest

print("=" * 70)
print("SecureMailScope - Framework Verification & Test Suite")
print("=" * 70)

# Verify project directories
os.makedirs("securemailscope", exist_ok=True)
os.makedirs("tests", exist_ok=True)
print("[+] Directories verified.")

# Test imports
try:
    import securemailscope
    from securemailscope.models import TLSSessionDetails, ForensicReport
    from securemailscope.traffic_processor import TrafficProcessor
    from securemailscope.crypto_validator import CryptographicValidator
    from securemailscope.ml_engine import MLRiskEngine
    from securemailscope.reporting import ForensicReportGenerator
    from securemailscope.api import app
    print("[+] Core modules loaded and verified successfully.")
except Exception as exc:
    print(f"[-] Import failure: {exc}")
    sys.exit(1)

# Run test suite
print("\n[+] Running automated test suite...")
loader = unittest.TestLoader()
suite = loader.discover("tests")
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)

if result.wasSuccessful():
    print("\n[SUCCESS] All tests passed! SecureMailScope framework is ready for production deployment.")
    sys.exit(0)
else:
    print("\n[FAIL] Verification failed. Check test outputs above.")
    sys.exit(1)
