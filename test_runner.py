import sys
from pathlib import Path
from oss_risk_agent.core.scanner import Scanner

def run_test(test_dir):
    print(f"--- Running test for {test_dir} ---")
    scanner = Scanner(f"tests/fixtures/{test_dir}")
    risks = scanner.scan()
    if not risks:
        print("No risks found.")
    for risk in risks:
        print(f"[{risk.severity.value}] {risk.category} - {risk.name}")
        print(f"  Target: {risk.target_file}:{risk.line_number if risk.line_number else 'N/A'}")
        print(f"  Desc:   {risk.description}")
        print(f"  Evid:   {risk.evidence}")
        print()
    print("-" * 50)

if __name__ == "__main__":
    run_test("go_project")
    run_test("rust_project")
    run_test("js_project")
