import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import xml.etree.ElementTree as ET

REPO = pathlib.Path.cwd()
C1 = REPO / ".artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1"
C2 = REPO / ".artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-2"
OUT = REPO / ".artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-3"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def run(*args):
    return subprocess.run(
        args, cwd=REPO, check=True, text=True, encoding="utf-8", stdout=subprocess.PIPE
    ).stdout


def verify_manifest(path, base):
    rows = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line:
            continue
        expected, name = line.split("  ", 1)
        target = base / name
        actual = sha256(target) if target.is_file() else None
        rows.append({"path": name, "expected": expected, "actual": actual, "match": expected == actual})
    return {
        "path": str(path.relative_to(REPO)).replace("\\", "/"),
        "entries": len(rows),
        "allMatch": all(row["match"] for row in rows),
        "mismatches": [row for row in rows if not row["match"]],
    }


def first_line(value):
    return str(value).splitlines()[0].strip()


OUT.mkdir(parents=True, exist_ok=True)
contract = load_json(C1 / "capture-contract.json")
capture = load_json(C2 / "affected-failures.sanitized.json")
results = load_json(C2 / "results.json")
classification = load_json(C2 / "failure-classification.json")
provenance = load_json(C2 / "console-capture-provenance.json")
diff_check = load_json(C2 / "diff-check.txt")

xml_tree = ET.parse(C2 / "affected.junit.xml")
xml_root = xml_tree.getroot()
xml_cases = list(xml_root.iter("test-case"))
xml_failed = [case for case in xml_cases if case.attrib.get("result") == "Failure"]
xml_outcomes = {}
for case in xml_cases:
    xml_outcomes[case.attrib.get("result")] = xml_outcomes.get(case.attrib.get("result"), 0) + 1

raw_xml_parse_error = None
try:
    ET.parse(C2 / "affected.junit.raw-sanitized.truncated.xml.txt")
except ET.ParseError as exc:
    raw_xml_parse_error = str(exc)

failures = capture["failures"]
explicit = [f for f in failures if f.get("identityResolution") == "emitted-by-detailed-capture"]
placeholders = [f for f in failures if str(f.get("identityResolution", "")).startswith("ordinal placeholder:")]
required_failure_fields = contract["affectedJson"]["failedTestRequiredFields"]

family_rows = {}
for failure in failures:
    key = failure["file"] + "\n" + first_line(failure["message"])
    family_rows.setdefault(key, []).append(failure)
recomputed_families = []
for key, members in family_rows.items():
    recomputed_families.append(
        {
            "familyId": hashlib.sha256(key.encode("utf-8")).hexdigest(),
            "count": len(members),
            "firstObservedIdentity": members[0]["identity"],
            "memberIdentities": [m["identity"] for m in members],
        }
    )
recomputed_families.sort(key=lambda x: (-x["count"], x["familyId"]))
observed_families = classification["families"]
classification_match = len(recomputed_families) == len(observed_families) and all(
    expected["familyId"] == actual["familyId"]
    and expected["count"] == actual["count"]
    and expected["firstObservedIdentity"] == actual["firstObservedIdentity"]
    and expected["memberIdentities"] == actual["memberIdentities"]
    for expected, actual in zip(recomputed_families, observed_families)
)

applicable_sanitized = [
    "affected.junit.xml",
    "affected-failures.sanitized.json",
    "results.json",
    "status-before.txt",
    "status-after.txt",
    "diff-check.txt",
]
repo_forms = {
    str(REPO),
    str(REPO).replace("\\", "/"),
    str(REPO).lower(),
    str(REPO).replace("\\", "/").lower(),
}
sanitization_findings = []
tenant_domain_re = re.compile(r"\b[a-z0-9][a-z0-9.-]*\.onmicrosoft\.com\b", re.I)
tenant_id_re = re.compile(
    r"(?i)\btenant[-_ ]?id\s*[:=]\s*[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b"
)
secret_re = re.compile(
    r"(?i)\b(?:bearer\s+[a-z0-9._~+/\-=]+|(?:client[-_ ]?secret|password|connection[-_ ]?string)\s*[:=]\s*(?!<REDACTED>)[^\s,;<>'\"&]+)"
)
for name in applicable_sanitized:
    text = (C2 / name).read_text(encoding="utf-8-sig", errors="replace")
    lowered = text.lower()
    if any(form in text or form in lowered for form in repo_forms):
        sanitization_findings.append({"file": name, "type": "absolute-repository-path"})
    if tenant_domain_re.search(text):
        sanitization_findings.append({"file": name, "type": "tenant-domain"})
    if tenant_id_re.search(text):
        sanitization_findings.append({"file": name, "type": "labeled-tenant-id"})
    if secret_re.search(text):
        sanitization_findings.append({"file": name, "type": "secret-pattern"})

c1_manifest = verify_manifest(C1 / "artifacts.sha256", C1)
c2_manifest = verify_manifest(C2 / "artifacts.sha256", C2)
c1_inputs = verify_manifest(C1 / "inputs.sha256", REPO)
c1_tracked = verify_manifest(C1 / "tracked-state-before.sha256", REPO)
c2_inputs_before = verify_manifest(C2 / "inputs-before.sha256", REPO)
c2_inputs_after = verify_manifest(C2 / "inputs-after.sha256", REPO)

console_path_match = re.search(
    r'console\s*=\s*pathlib\.Path\(\s*r"([^"]+)"\s*r"([^"]+)"',
    (C2 / "recover-failures.py").read_text(encoding="utf-8"),
    re.S,
)
console_path = pathlib.Path("".join(console_path_match.groups())) if console_path_match else None
console_present = bool(console_path and console_path.is_file())
console_hash = sha256(console_path) if console_present else None
console_text = console_path.read_text(encoding="utf-8", errors="replace") if console_present else ""
lifecycle = {
    "pesterVersionMarkers": len(re.findall(r"^Pester v", console_text, re.M)),
    "discoveryStartMarkers": len(re.findall(r"^Starting discovery", console_text, re.M)),
    "discoveryFoundMarkers": len(re.findall(r"^Discovery found", console_text, re.M)),
    "runStartMarkers": len(re.findall(r"^Running tests\.$", console_text, re.M)),
    "completionMarkers": len(re.findall(r"^Tests completed in", console_text, re.M)),
    "summaryMarkers": len(re.findall(r"^Tests Passed:", console_text, re.M)),
}

started = dt.datetime.strptime(capture["startedUtc"], "%Y-%m-%dT%H:%M:%S.%f0Z").replace(tzinfo=dt.timezone.utc)
ended = dt.datetime.strptime(capture["endedUtc"], "%Y-%m-%dT%H:%M:%S.%f0Z").replace(tzinfo=dt.timezone.utc)
git_head = run("git", "rev-parse", "HEAD").strip()
git_diff_names = run("git", "diff", "--name-only").splitlines()
git_status = run("git", "status", "--short").splitlines()

expected_hashes = {
    "affected.junit.xml": "d637b8fc2e8afdbb5067e62e32cd6961255230a68d6342aa38b7c2ff0fefe7a0",
    "affected-failures.sanitized.json": "b446775bd05d07a211ee8dc598371d4e515b31e0849f7accfcf3551173a362cd",
    "results.json": "7aef08cde733f00d2bebba528b9ab4c4d2b79facebd7631dc4651c91497bf8af",
    "failure-classification.json": "97158901238d61fe6acb82a74c5443b0959cfd5775f6bf371bf23b58954df3c4",
    "handoff.json": "47c8e7b95704a2fadf50acf1b95135e7ef0982f85292fa13768ed3d4984389ad",
}
hash_checks = {
    name: {"expected": expected, "actual": sha256(C2 / name), "match": expected == sha256(C2 / name)}
    for name, expected in expected_hashes.items()
}

clauses = [
    {
        "clause": "exact command identity",
        "verdict": "PASS",
        "evidence": {
            "actualSha256": sha256(C1 / "exact-command.txt"),
            "contractSha256": contract["canonicalCommand"]["sha256"],
            "resultsSha256": results["sourceHashes"]["exactCommand"],
        },
    },
    {
        "clause": "exactly one Pester invocation and retry zero",
        "verdict": "PASS_WITH_PROVENANCE_LIMITATION",
        "evidence": {
            "reportedInvocationCount": results["invocationCount"],
            "reportedRetryCount": results["retryCount"],
            "consoleLifecycle": lifecycle,
            "consolePresentOutsideCanonicalRoot": console_present,
            "consoleHashMatchesProvenance": console_hash == provenance["consoleSha256"],
        },
        "limitation": "One complete lifecycle is evidenced in an external temporary console file; the canonical C2 root retains only its hash, not the console bytes.",
    },
    {
        "clause": "JSON and canonical XML parse",
        "verdict": "PASS_WITH_RECONSTRUCTION_LIMITATION",
        "evidence": {
            "jsonParsed": True,
            "canonicalXmlParsed": True,
            "nativeWriterXmlParsed": raw_xml_parse_error is None,
            "nativeWriterParseError": raw_xml_parse_error,
            "canonicalXmlWasReconstructed": True,
        },
    },
    {
        "clause": "count arithmetic and cardinality reconciliation",
        "verdict": "PASS",
        "evidence": {
            "total": capture["total"],
            "sumOutcomes": capture["passed"] + capture["failed"] + capture["skipped"] + capture["notRun"],
            "jsonFailures": len(failures),
            "xmlCases": len(xml_cases),
            "xmlFailed": len(xml_failed),
            "xmlOutcomes": xml_outcomes,
            "failedContainers": capture["failedContainers"],
        },
    },
    {
        "clause": "every failed-test identity and details map one-to-one without fabrication",
        "verdict": "NACK",
        "evidence": {
            "requiredRecords": capture["failed"],
            "explicitRecoveredIdentities": len(explicit),
            "ordinalPlaceholderIdentities": len(placeholders),
            "jsonXmlIdentityEquality": all(
                failure["identity"] == case.attrib.get("name") for failure, case in zip(failures, xml_failed)
            ),
            "canonicalXmlDerivedFromSameRecoveredJson": True,
        },
        "reason": "The 72 BeforeAll-derived records use invented ordinal identities/names, not corresponding Pester failed-test identities. JSON-to-XML equality is circular because the canonical XML was rebuilt from that JSON.",
    },
    {
        "clause": "required failed-test fields",
        "verdict": "PASS_FOR_SHAPE_ONLY",
        "evidence": {
            "records": len(failures),
            "missingRequiredFieldCounts": {
                field: sum(field not in failure for failure in failures) for field in required_failure_fields
            },
            "uniqueIdentities": len({failure["identity"] for failure in failures}),
            "positiveOrExplicitNullLines": all(
                failure["line"] is None
                or (isinstance(failure["line"], int) and not isinstance(failure["line"], bool) and failure["line"] > 0)
                for failure in failures
            ),
        },
        "limitation": "Shape validity does not cure the 72 unresolved identities.",
    },
    {
        "clause": "timestamps, tool versions, native and semantic exits",
        "verdict": "NACK",
        "evidence": {
            "startedUtc": capture["startedUtc"],
            "endedUtc": capture["endedUtc"],
            "ordered": ended >= started,
            "durationSeconds": (ended - started).total_seconds(),
            "toolVersions": results["toolVersions"],
            "reportedNativeExit": results["nativeExit"],
            "derivedSemanticExit": 0 if capture["failed"] == 0 and capture["failedContainers"] == 0 else 1,
            "reportedSemanticExit": results["semanticExit"],
        },
        "reason": "semanticExit=1 is mechanically derivable, but nativeExit=0 is assigned later by finalize-capture.ps1 and no native process-exit record is retained.",
    },
    {
        "clause": "sanitization",
        "verdict": "PASS_FOR_CONTRACT_APPLICABLE_ARTIFACTS",
        "evidence": {
            "filesScanned": applicable_sanitized,
            "forbiddenFindings": sanitization_findings,
        },
        "limitation": "The external temporary console is unsanitized and is not present in the canonical C2 evidence root; generic GUIDs were not treated as tenant IDs without tenant labeling.",
    },
    {
        "clause": "input and tracked-state stability with diff check",
        "verdict": "PASS",
        "evidence": {
            "inputsBeforeAfterByteEqual": (C2 / "inputs-before.sha256").read_bytes()
            == (C2 / "inputs-after.sha256").read_bytes(),
            "statusBeforeAfterByteEqual": (C2 / "status-before.txt").read_bytes()
            == (C2 / "status-after.txt").read_bytes(),
            "manifests": [c1_inputs, c1_tracked, c2_inputs_before, c2_inputs_after],
            "diffCheck": diff_check,
            "currentHead": git_head,
            "currentTrackedDiffNames": git_diff_names,
            "currentStatus": git_status,
        },
    },
    {
        "clause": "deterministic classification and causal separation",
        "verdict": "PASS_FOR_GROUPING_NACK_FOR_REMEDIATION_ATOMICITY",
        "evidence": {
            "familyCount": len(observed_families),
            "familyMemberCount": sum(family["count"] for family in observed_families),
            "sharedCandidateCount": len(classification["rootOrSharedCauseCandidates"]),
            "downstreamSymptomCount": len(classification["downstreamSymptoms"]),
            "mechanicalRecomputationMatches": classification_match,
            "earliestObserved": classification["earliestObserved"],
            "causalityLimit": classification["causalityLimit"],
        },
        "reason": "Grouping is deterministic and appropriately labels hypotheses, but it neither establishes earliest shared cause nor separates causes from symptoms sufficiently to define 12 truthful atomic remediation cards.",
    },
]

verification = {
    "schema": "REG-001-D02/independent-verification/v1",
    "card": "REG-001-D02",
    "generation": 685,
    "role": "Platinum/Coworker-3",
    "overallVerdict": "NACK",
    "verifiedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "hashChecks": hash_checks,
    "artifactManifestChecks": [c1_manifest, c2_manifest],
    "clauses": clauses,
    "smallestTruthfulFollowUp": {
        "rerunAuthorizedHere": False,
        "required": "Under a new explicit authorization, perform one fresh capture with an XML-safe reporter or pre-sanitized reporter input and retain the native structured Pester result plus native process-exit metadata. It must preserve all 833 actual failed-test identities/details, especially the 72 BeforeAll-affected tests. Then causally inspect/reclassify the earliest shared prerequisites before creating 12 atomic remediation cards.",
    },
}

commands = {
    "schema": "REG-001-D02/independent-verification-commands/v1",
    "pesterInvoked": False,
    "networkUsed": False,
    "commands": [
        "python .artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-3/verify_reg001_d02.py",
        "python -m json.tool .artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-3/verification-results.json",
    ],
    "mechanicalOperations": [
        "SHA-256 hashing of C1/C2 files and manifest targets",
        "JSON parsing",
        "ElementTree XML parsing without recovery",
        "count and identity reconciliation",
        "sanitization-pattern scans",
        "deterministic family recomputation",
        "read-only git rev-parse, diff --name-only, and status --short",
    ],
}

(OUT / "verification-results.json").write_text(
    json.dumps(verification, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)
(OUT / "commands-executed.json").write_text(
    json.dumps(commands, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)
print(json.dumps({"overallVerdict": "NACK", "clauses": len(clauses)}, separators=(",", ":")))
