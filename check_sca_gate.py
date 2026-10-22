import json
import os
import sys

MAX_CRITICAL = 0
MAX_HIGH = 2


def get_severity(vulnerability):

    ranks = {
        "UNKNOWN": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    severity = str(
        vulnerability.get("severity", "UNKNOWN")
    ).upper()

    if severity not in ranks:
        severity = "UNKNOWN"

    for field in ("cvssv4", "cvssv3", "cvssv2"):
        cvss = vulnerability.get(field, {})

        if not isinstance(cvss, dict):
            continue

        try:
            score = float(cvss["baseScore"])
        except (KeyError, TypeError, ValueError):
            continue

        if score >= 9.0:
            calculated = "CRITICAL"
        elif score >= 7.0:
            calculated = "HIGH"
        elif score >= 4.0:
            calculated = "MEDIUM"
        else:
            calculated = "LOW"

        if ranks[calculated] > ranks[severity]:
            severity = calculated

    return severity


def main():
    report_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "reports/dependency-check-report.json"
    )

    try:
        with open(report_path, encoding="utf-8") as file:
            report = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        print("ERROR: Cannot read SCA report:", error)
        sys.exit(2)

    dependencies = report.get("dependencies")

    if not isinstance(dependencies, list):
        print("ERROR: Invalid Dependency-Check report")
        sys.exit(2)

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    print("=== OWASP SCA RESULTS ===")

    for dependency in dependencies:
        component = dependency.get("fileName", "Unknown")
        vulnerabilities = (
            dependency.get("vulnerabilities") or []
        )

        for vulnerability in vulnerabilities:
            severity = get_severity(vulnerability)
            cve = vulnerability.get("name", "Unknown")

            counts[severity] += 1

            print(f"{severity}: {cve} | {component}")

    critical = counts["CRITICAL"]
    high = counts["HIGH"]

    print("\n=== QUALITY GATE ===")
    print(f"CRITICAL: {critical} (allowed: 0)")
    print(f"HIGH: {high} (allowed: 0-2)")
    print(f"MEDIUM: {counts['MEDIUM']}")
    print(f"LOW: {counts['LOW']}")
    print(f"UNKNOWN: {counts['UNKNOWN']}")

    passed = (
        critical <= MAX_CRITICAL
        and high <= MAX_HIGH
    )

    status = "PASS" if passed else "FAIL"

    print(f"\nQuality Gate: {status}")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    if summary_path:
        with open(
            summary_path, "a", encoding="utf-8"
        ) as summary:
            summary.write("## SCA Quality Gate\n\n")
            summary.write("| Severity | Count |\n")
            summary.write("|---|---:|\n")

            for severity, count in counts.items():
                summary.write(
                    f"| {severity} | {count} |\n"
                )

            summary.write(
                f"\n**Quality Gate: {status}**\n"
            )

    if not passed:
        print("Security policy violated!")
        sys.exit(1)

    print("Security policy passed.")


if __name__ == "__main__":
    main()
