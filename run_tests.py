"""VOIDTRACE Automated Test Runner.

Executes all unit and integration test suites and displays execution timing.
"""

from __future__ import annotations

import os
import sys
import time
import unittest

# Ensure workspace root is always at the beginning of sys.path
WORKSPACE_ROOT = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

def run_all_tests() -> bool:
    print("=" * 70, flush=True)
    print("VOIDTRACE TEST RUNNER", flush=True)
    print("=" * 70, flush=True)

    start_time = time.perf_counter()
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(WORKSPACE_ROOT, "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    duration = time.perf_counter() - start_time
    print("=" * 70, flush=True)
    print(f"Tests Run: {result.testsRun} | Errors: {len(result.errors)} | Failures: {len(result.failures)}", flush=True)
    print(f"Total Execution Time: {duration:.3f} seconds", flush=True)
    print("=" * 70, flush=True)

    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
