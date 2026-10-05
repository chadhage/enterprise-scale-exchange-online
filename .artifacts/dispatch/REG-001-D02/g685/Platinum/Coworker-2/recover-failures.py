import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET

root = pathlib.Path(".artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-2")
console = pathlib.Path(
    r"C:\Users\chhage\AppData\Local\Temp"
    r"\1790950281866-copilot-tool-output-2912-600200e9-c5d0-4a09-ab0d-bcd6d93d2b6d.txt"
)
repo = str(pathlib.Path.cwd())


def protect(value):
    value = "" if value is None else str(value)
    value = re.sub(re.escape(repo), "<REPO>", value, flags=re.I)
    value = re.sub(re.escape(repo.replace("\\", "/")), "<REPO>", value, flags=re.I)
    value = re.sub(
        r"\b[a-z0-9][a-z0-9.-]*\.onmicrosoft\.com\b",
        "<TENANT_DOMAIN>",
        value,
        flags=re.I,
    )
    value = re.sub(r"\bBearer\s+[A-Za-z0-9._~+/\-=]+", "Bearer <REDACTED>", value, flags=re.I)
    value = re.sub(
        r"((?:client[-_ ]?secret|password|credential|connection[-_ ]?string)\s*[:=]\s*)[^\s,;<>'\"&]+",
        r"\1<REDACTED>",
        value,
        flags=re.I,
    )
    value = re.sub(
        r"((?:tenant[-_ ]?id)\s*[:=]\s*)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        r"\1<TENANT_ID>",
        value,
        flags=re.I,
    )
    return value


raw = console.read_text(encoding="utf-8", errors="replace")
raw = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw)
lines = raw.splitlines()

current_file = ""
describe = ""
context = ""
records = []
container_message = ""
container_position = ""
i = 0
while i < len(lines):
    line = lines[i]
    match = re.match(r"^Running tests from '(.+)'$", line)
    if match:
        current_file = protect(match.group(1))
        describe = ""
        context = ""
        i += 1
        continue
    match = re.match(r"^\s*Describing\s+(.+)$", line)
    if match:
        describe = match.group(1).strip()
        context = ""
        i += 1
        continue
    match = re.match(r"^\s*Context\s+(.+)$", line)
    if match:
        context = match.group(1).strip()
        i += 1
        continue
    match = re.match(r"^\s*\[-\]\s+(.+)$", line)
    if not match:
        i += 1
        continue

    label = match.group(1).strip()
    detail = []
    j = i + 1
    while j < len(lines):
        next_line = lines[j]
        if (
            re.match(r"^\s*\[(?:\+|-)\]\s+", next_line)
            or next_line.startswith("Running tests from '")
            or re.match(r"^\s*(?:Describing|Context)\s+", next_line)
            or next_line.startswith("Tests completed in ")
        ):
            break
        if next_line.strip():
            detail.append(next_line.strip())
        j += 1

    if label.endswith(" failed with:") and "ExchangeEvidenceSigning.Tests.ps1" in label:
        container_message = protect(detail[0] if detail else label)
        container_position = protect("\n".join(detail[1:]))
        i = j
        continue

    name = re.sub(r"\s+\d+(?:\.\d+)?(?:ms|s)\s+\([^)]*\)\s*$", "", label).strip()
    identity_parts = [part for part in (current_file, describe, context, name) if part]
    message = protect(detail[0] if detail else "Failure detail was not emitted.")
    position = protect("\n".join(detail[1:]))
    line_number = None
    for candidate in reversed(detail):
        line_match = re.search(r":(\d+)\s*$", candidate)
        if line_match:
            line_number = int(line_match.group(1))
            break
    records.append(
        {
            "identity": protect(" > ".join(identity_parts)),
            "name": protect(name),
            "file": current_file,
            "line": line_number,
            "message": message,
            "position": position,
            "identityResolution": "emitted-by-detailed-capture",
        }
    )
    i = j

explicit_count = len(records)
expected_failed = 833
unresolved_count = expected_failed - explicit_count
if explicit_count != 761 or unresolved_count != 72:
    raise RuntimeError(
        "Unexpected detailed capture cardinality: explicit=%d unresolved=%d"
        % (explicit_count, unresolved_count)
    )

# Detailed output can repeat a display name for data-driven cases. Preserve the
# captured display identity and add only a stable occurrence suffix when needed.
identity_counts = {}
used_identities = set()
for record in records:
    base = record["identity"]
    identity_counts[base] = identity_counts.get(base, 0) + 1
    candidate = base
    while candidate.casefold() in used_identities:
        identity_counts[base] += 1
        candidate = "%s > captured-occurrence-%03d" % (
            base,
            identity_counts[base],
        )
    record["identity"] = candidate
    used_identities.add(candidate.casefold())

container_file = (
    "samples/contoso-exchange-online-managed-service/tests/unit/"
    "ExchangeEvidenceSigning.Tests.ps1"
)
for number in range(1, unresolved_count + 1):
    records.append(
        {
            "identity": "ExchangeEvidenceSigning.Tests.ps1 > "
            "BeforeAll-derived failed test identity unavailable > ordinal-%03d" % number,
            "name": "BeforeAll-derived failed test identity unavailable ordinal-%03d" % number,
            "file": container_file,
            "line": 20,
            "message": container_message,
            "position": container_position,
            "identityResolution": (
                "ordinal placeholder: native capture counted this failed test but did not emit "
                "its discovered identity after the container BeforeAll failure"
            ),
        }
    )

prior = json.loads((root / "affected-failures.sanitized.json").read_text(encoding="utf-8"))
capture = {
    "schema": "REG-001-D02/v1",
    "generation": 685,
    "retryCount": 0,
    "startedUtc": prior["startedUtc"],
    "endedUtc": prior["endedUtc"],
    "total": 6292,
    "passed": 5459,
    "failed": 833,
    "skipped": 0,
    "notRun": 0,
    "failedContainers": 1,
    "result": "Failed",
    "failures": records,
    "captureLimitation": {
        "nativeNUnitWriter": "truncated on XML-illegal ESC diagnostic character",
        "structuredPesterResult": "overwritten by the End-step export exception",
        "explicitFailedIdentitiesRecoveredFromDetailedOutput": explicit_count,
        "failedIdentitiesUnavailableAfterBeforeAll": unresolved_count,
        "placeholderPolicy": "unique stable ordinals; no test identity or causality fabricated",
    },
}
(root / "affected-failures.sanitized.json").write_text(
    json.dumps(capture, indent=2, ensure_ascii=False), encoding="utf-8"
)

test_results = ET.Element(
    "test-results",
    {
        "name": "Pester",
        "total": "6292",
        "errors": "0",
        "failures": "833",
        "not-run": "0",
        "inconclusive": "0",
        "ignored": "0",
        "skipped": "0",
    },
)
suite = ET.SubElement(
    test_results,
    "test-suite",
    {"name": "REG-001-D02 sole affected-suite capture", "result": "Failed"},
)
results = ET.SubElement(suite, "results")
for number in range(1, 5460):
    ET.SubElement(
        results,
        "test-case",
        {
            "name": "captured-pass-count-%05d" % number,
            "description": (
                "Count-preserving placeholder; the native NUnit writer was truncated."
            ),
            "result": "Success",
            "executed": "True",
        },
    )
for failure in records:
    case = ET.SubElement(
        results,
        "test-case",
        {
            "name": failure["identity"],
            "description": failure["name"],
            "result": "Failure",
            "executed": "True",
        },
    )
    node = ET.SubElement(case, "failure")
    ET.SubElement(node, "message").text = failure["message"]
    ET.SubElement(node, "stack-trace").text = failure["position"]
ET.ElementTree(test_results).write(
    root / "affected.junit.xml", encoding="utf-8", xml_declaration=True
)

provenance = {
    "schema": "REG-001-D02/console-recovery/v1",
    "consoleSha256": hashlib.sha256(console.read_bytes()).hexdigest(),
    "summaryCounts": {
        "total": 6292,
        "passed": 5459,
        "failed": 833,
        "skipped": 0,
        "notRun": 0,
        "failedContainers": 1,
    },
    "explicitFailureRecords": explicit_count,
    "beforeAllDerivedIdentityPlaceholders": unresolved_count,
    "retryOrAdditionalPesterInvocation": False,
}
(root / "console-capture-provenance.json").write_text(
    json.dumps(provenance, indent=2), encoding="utf-8"
)

print(
    "recovered explicit=%d unresolved=%d total=%d"
    % (explicit_count, unresolved_count, len(records))
)
