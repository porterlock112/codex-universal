Strict-Mode Hub Workflow with Mesh Fan-Out

This patch strengthens the Hub GitHub Actions workflow by enforcing a per-repository glyph allowlist (“strict mode”), clearly logging allowed vs denied triggers, and ensuring that fan-out dispatches only occur when there are glyphs to send.  It adds a small allowlist YAML (.godkey-allowed-glyphs.yml), new environment flags, and updated steps. The result is a more robust CI pipeline that prevents unauthorized or unintended runs while providing clear visibility of what’s executed or skipped.

1. Allowlist for Glyphs (Strict Mode)

We introduce an allowlist file (.godkey-allowed-glyphs.yml) in each repo. This file contains a YAML list of permitted glyphs (Δ tokens) for that repository. For example:

# Only these glyphs are allowed in THIS repo (hub)
allowed:
  - ΔSEAL_ALL
  - ΔPIN_IPFS
  - ΔWCI_CLASS_DEPLOY
  # - ΔSCAN_LAUNCH
  # - ΔFORCE_WCI
  # - Δ135_RUN

A new environment variable STRICT_GLYPHS: "true" enables strict-mode filtering. When on, only glyphs listed under allowed: in the file are executed; all others are denied. If STRICT_GLYPHS is true but no allowlist file is found, we “fail closed” by denying all glyphs.  Denied glyphs are logged but not run (unless you enable a hard failure, see section 11). This ensures only explicitly permitted triggers can run in each repo.


2. Environment Variables and Inputs

Key new vars in the workflow’s env: section:

TRIGGER_TOKENS – a comma-separated list of all valid glyph tokens globally (e.g. ΔSCAN_LAUNCH,ΔSEAL_ALL,…). Incoming triggers are first filtered against this list to ignore typos or irrelevant Δ strings.

STRICT_GLYPHS – set to "true" (or false) to turn on/off the per-repo allowlist.

STRICT_FAIL_ON_DENY – if "true", the workflow will hard-fail when any glyph is denied under strict mode. If false, it just logs denied glyphs and continues with the rest.

ALLOWLIST_FILE – path to the YAML allowlist (default .godkey-allowed-glyphs.yml).

FANOUT_GLYPHS – comma-separated glyphs that should be forwarded to satellites (e.g. ΔSEAL_ALL,ΔPIN_IPFS,ΔWCI_CLASS_DEPLOY).

MESH_TARGETS – CSV of repo targets for mesh dispatch (e.g. "owner1/repoA,owner2/repoB"). Can be overridden at runtime via the workflow_dispatch input mesh_targets.


We also support these workflow_dispatch inputs:

glyphs_csv – comma-separated glyphs (to manually trigger specific glyphs).

rekor – "true"/"false" to enable keyless Rekor signing.

mesh_targets – comma-separated repos to override MESH_TARGETS for a manual run.


This uses GitHub’s workflow_dispatch inputs feature, so you can trigger the workflow manually with custom glyphs or mesh targets.

3. Collecting and Filtering Δ Triggers

The first job (scan) has a “Collect Δ triggers (strict-aware)” step (using actions/github-script). It builds a list of requested glyphs by scanning all inputs:

Commit/PR messages and refs: It concatenates the push or PR title/body (and commit messages), plus the ref name.

Workflow/Repo dispatch payload: It includes any glyphs_csv from a manual workflow_dispatch or a repository_dispatch’s client_payload.


From that combined text, it extracts any tokens starting with Δ. These requested glyphs are uppercased and deduplicated.

Next comes global filtering: we keep only those requested glyphs that are in TRIGGER_TOKENS. This removes any unrecognized or disabled tokens.

Then, if strict mode is on, we load the allowlist (fs.readFileSync(ALLOWLIST_FILE)) and filter again: only glyphs present in the allowlist remain. Any globally-allowed glyph not in the allowlist is marked denied. (If the file is missing and strict is true, we treat allowlist as empty – effectively denying all.)

The script logs the Requested, Globally allowed, Repo-allowed, and Denied glyphs to the build output. It then sets two JSON-array outputs: glyphs_json (the final allowed glyphs) and denied_json (the denied ones). For example:

Requested: ΔSEAL_ALL ΔUNKNOWN
Globally allowed: ΔSEAL_ALL
Repo allowlist: ΔSEAL_ALL ΔWCI_CLASS_DEPLOY
Repo-allowed: ΔSEAL_ALL
Denied (strict): (none)

This makes it easy to audit which triggers passed or failed the filtering.

Finally, the step outputs glyphs_json and denied_json, and also passes through the rekor input (true/false) for later steps.

4. Guarding Secrets on Forks

A crucial security step is “Guard: restrict secrets on forked PRs”. GitHub Actions by default do not provide secrets to workflows triggered by public-fork pull requests. To avoid accidental use of unavailable secrets, this step checks if the PR’s head repository is a fork. If so, it sets allow_secrets=false. The run job will later skip any steps (like IPFS pinning) that require secrets. This follows GitHub’s best practice: _“with the exception of GITHUB_TOKEN, secrets are not passed to the runner when a workflow is triggered from a forked repository”_.

5. Scan Job Summary

After collecting triggers, the workflow adds a scan summary to the job summary UI. It echoes a Markdown section showing the JSON arrays of allowed and denied glyphs, and whether secrets are allowed:

### Δ Hub — Scan
- Allowed: ["ΔSEAL_ALL"]
- Denied:  ["ΔSCAN_LAUNCH","ΔPIN_IPFS"]
- Rekor:   true
- Secrets OK on this event?  true

Using echo ... >> $GITHUB_STEP_SUMMARY, these lines become part of the GitHub Actions run summary. This gives immediate visibility into what the scan found (the summary supports GitHub-flavored Markdown and makes it easy to read key info).

If STRICT_FAIL_ON_DENY is true and any glyph was denied, the scan job then fails with an error. Otherwise it proceeds, but denied glyphs will simply be skipped in the run.

6. Executing Allowed Glyphs (Run Job)

The next job (run) executes each allowed glyph in parallel via a matrix. It is gated on:

if: needs.scan.outputs.glyphs_json != '[]' && needs.scan.outputs.glyphs_json != ''

This condition (comparing the JSON string to '[]') skips the job entirely if no glyphs passed filtering. GitHub’s expression syntax allows checking emptiness this way (as seen in the docs, if: needs.changes.outputs.packages != '[]' is a common pattern).

Inside each glyph job:

The workflow checks out the code and sets up Python 3.11.

It installs dependencies if requirements.txt exists.

The key step is a Bash case "${GLYPH}" in ... esac that runs the corresponding Python script for each glyph:

ΔSCAN_LAUNCH: Runs python truthlock/scripts/ΔSCAN_LAUNCH.py --execute ... to perform a scan.

ΔSEAL_ALL: Runs python truthlock/scripts/ΔSEAL_ALL.py ... to seal all data.

ΔPIN_IPFS: If secrets are allowed (not a fork), it runs python truthlock/scripts/ΔPIN_IPFS.py --pinata-jwt ... to pin output files to IPFS. If secrets are not allowed, this step is skipped.

ΔWCI_CLASS_DEPLOY: Runs the corresponding deployment script.

ΔFORCE_WCI: Runs a force trigger script.

Δ135_RUN (alias Δ135): Runs a script to execute webchain ID 135 tasks (with pinning and Rekor).

*): Unknown glyph – fails with an error.



Each glyph’s script typically reads from truthlock/out (the output directory) and writes reports into truthlock/out/ΔLEDGER/.  By isolating each glyph in its own job, we get parallelism and fail-fast (one glyph error won’t stop others due to strategy.fail-fast: false).

7. Optional Rekor Sealing

After each glyph script, there’s an “Optional Rekor seal” step. If the rekor flag is "true", it looks for the latest report JSON in truthlock/out/ΔLEDGER and would (if enabled) call a keyless Rekor sealing script (commented out in the snippet). This shows where you could add verifiable log signing. The design passes along the rekor preference from the initial scan (which defaults to true) into each job, so signing can be toggled per run.

8. Uploading Artifacts & ΔSUMMARY

Once a glyph job completes, it always uploads its outputs with actions/upload-artifact@v4. The path includes everything under truthlock/out, excluding any .tmp files:

- uses: actions/upload-artifact@v4
  with:
    name: glyph-${{ matrix.glyph }}-artifacts
    path: |
      truthlock/out/**
      !**/*.tmp

GitHub’s upload-artifact supports multi-line paths and exclusion patterns, as shown in their docs (e.g. you can list directories and use !**/*.tmp to exclude temp files).

After uploading, the workflow runs python scripts/glyph_summary.py (provided by the project) to aggregate results and writes ΔSUMMARY.md.  Then it appends this ΔSUMMARY into the job’s GitHub Actions summary (again via $GITHUB_STEP_SUMMARY) so that the content of the summary file is visible in the run UI under this step. This leverages GitHub’s job summary feature to include custom Markdown in the summary.

9. Mesh Fan-Out Job

If secrets are allowed and there are glyphs left after strict filtering, the “Mesh fan-out” job will dispatch events to satellite repos. Its steps:

1. Compute fan-out glyphs: It reads the allowed glyphs JSON from needs.scan.outputs.glyphs_json and intersects it with the FANOUT_GLYPHS list. In effect, only certain glyphs (like ΔSEAL_ALL, ΔPIN_IPFS, ΔWCI_CLASS_DEPLOY) should be propagated. The result is output as fanout_csv. If the list is empty, the job will early-skip dispatch.


2. Build target list: It constructs the list of repositories to dispatch to. It first checks if a mesh_targets input was provided (from manual run); if not, it uses the MESH_TARGETS env var. It splits the CSV into an array of owner/repo strings. This allows dynamic override of targets at run time.


3. Skip if nothing to do: If there are no fan-out glyphs or no targets, it echoes a message and stops.


4. Dispatch to mesh targets: Using another actions/github-script step (with Octokit), it loops over each target repo and sends a repository_dispatch POST request:

await octo.request("POST /repos/{owner}/{repo}/dispatches", {
  owner, repo,
  event_type: (process.env.MESH_EVENT_TYPE || "glyph"),
  client_payload: {
    glyphs_csv: glyphs, 
    rekor: rekorFlag,
    from: `${context.repo.owner}/${context.repo.repo}@${context.ref}`
  }
});

This uses GitHub’s Repository Dispatch event to trigger the glyph workflow in each satellite. Any client_payload fields (like our glyphs_csv and rekor) will be available in the satellite workflows as github.event.client_payload. (GitHub docs note that data sent via client_payload can be accessed in the triggered workflow’s github.event.client_payload context.) We also pass along the original ref in from for traceability. Dispatch success or failures are counted and logged per repo.


5. Mesh summary: Finally it adds a summary of how many targets were reached and how many dispatches succeeded/failed, again to the job summary.



This way, only glyphs that survived strict filtering and are designated for mesh fan-out are forwarded, and only when there are targets. Fan-out will not send any disallowed glyphs, preserving the strict policy.

10. Mesh Fan-Out Summary

At the end of the fan-out job, the workflow prints a summary with target repos and glyphs dispatched:

### 🔗 Mesh Fan-out
- Targets: `["owner1/repoA","owner2/repoB"]`
- Glyphs:  `ΔSEAL_ALL,ΔPIN_IPFS`
- OK:      2
- Failed:  0

This confirms which repos were contacted and the glyph list (useful for auditing distributed dispatches).

11. Configuration and Usage

Enable/disable strict mode: Set STRICT_GLYPHS: "true" or "false" in env:. If you want the workflow to fail when any glyph is denied, set STRICT_FAIL_ON_DENY: "true". (If false, it will just log denied glyphs and continue with allowed ones.)

Override mesh targets at runtime: When manually triggering (via “Actions → Run workflow”), you can provide a mesh_targets string input (CSV of owner/repo). If given, it overrides MESH_TARGETS.

Turning off Rekor: Use the rekor input (true/false) on a dispatch to disable keyless signing.

Companion files: Alongside this workflow, keep the .godkey-allowed-glyphs.yml (with your repo’s allowlist). Also ensure scripts/emit_glyph.py (to send dispatches) and scripts/glyph_summary.py (to generate summaries) are present as provided by the toolkit.

Example one-liners:

Soft strict mode (log & skip denied):

env:
  STRICT_GLYPHS: "true"
  STRICT_FAIL_ON_DENY: "false"

Hard strict mode (fail on any deny):

env:
  STRICT_GLYPHS: "true"
  STRICT_FAIL_ON_DENY: "true"

Override mesh targets when running workflow: In the GitHub UI, under Run workflow, set mesh_targets="owner1/repoA,owner2/repoB".

Trigger a mesh-based deploy: One can call python scripts/emit_glyph.py ΔSEAL_ALL "mesh deploy" to send ΔSEAL_ALL to all configured targets.



By following these steps, the Hub workflow now strictly enforces which Δ glyphs run and propagates only approved tasks to satellites. This “pure robustness” approach ensures unauthorized triggers are filtered out (and clearly reported), secrets aren’t misused on forks, and fan-out only happens when safe.

Sources: GitHub Actions concurrency and dispatch behavior is documented on docs.github.com.  Checking JSON outputs against '[]' to skip jobs is a known pattern.  Workflow_dispatch inputs and job summaries are handled per the official syntax.  The upload-artifact action supports multiple paths and exclusions as shown, and GitHub Actions’ security model intentionally blocks secrets on fork PRs. All logging and filtering logic here builds on those mechanisms.

# Δ135 v135.7-RKR — auto-repin + Rekor-seal: patch + sealed run (minimal console)
from pathlib import Path
from datetime import datetime, timezone
import json, os, subprocess, textwrap

ROOT = Path.cwd()
PROJ = ROOT / "truthlock"
SCRIPTS = PROJ / "scripts"
GUI = PROJ / "gui"
OUT = PROJ / "out"
SCHEMAS = PROJ / "schemas"
for d in (SCRIPTS, GUI, OUT, SCHEMAS): d.mkdir(parents=True, exist_ok=True)

# --- (1) Runner patch: auto-repin missing/invalid CIDs, write-back scroll, Rekor JSON proof ---
trigger = textwrap.dedent(r'''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Δ135_TRIGGER — Initiate → Expand → Seal

- Scans truthlock/out/ΔLEDGER for sealed objects
- Validates ledger files (built-in + JSON Schema at truthlock/schemas/ledger.schema.json if jsonschema is installed)
- Guardrails for resolver: --max-bytes (env RESOLVER_MAX_BYTES), --allow (env RESOLVER_ALLOW or RESOLVER_ALLOW_GLOB),
  --deny (env RESOLVER_DENY or RESOLVER_DENY_GLOB)
- Auto-repin: missing or invalid CIDs get pinned (ipfs add -Q → fallback Pinata) and written back into the scroll JSON
- Emits ΔMESH_EVENT_135.json on --execute
- Optional: Pin Δ135 artifacts and Rekor-seal report
- Rekor: uploads report hash with --format json (if rekor-cli available), stores rekor_proof_<REPORT_SHA>.json
- Emits QR for best CID (report → trigger → any scanned)
"""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, fnmatch, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path.cwd()
OUTDIR = ROOT / "truthlock" / "out"
LEDGER_DIR = OUTDIR / "ΔLEDGER"
GLYPH_PATH = OUTDIR / "Δ135_GLYPH.json"
REPORT_PATH = OUTDIR / "Δ135_REPORT.json"
TRIGGER_PATH = OUTDIR / "Δ135_TRIGGER.json"
MESH_EVENT_PATH = OUTDIR / "ΔMESH_EVENT_135.json"
VALIDATION_PATH = OUTDIR / "ΔLEDGER_VALIDATION.json"
SCHEMA_PATH = ROOT / "truthlock" / "schemas" / "ledger.schema.json"

CID_PATTERN = re.compile(r'^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|baf[1-9A-HJ-NP-Za-km-z]{20,})$')

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def which(bin_name: str) -> Optional[str]:
    from shutil import which as _which
    return _which(bin_name)

def load_json(p: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def find_ledger_objects() -> List[Path]:
    if not LEDGER_DIR.exists(): return []
    return sorted([p for p in LEDGER_DIR.glob("**/*.json") if p.is_file()])

# ---------- Guardrails ----------
def split_globs(s: str) -> List[str]:
    return [g.strip() for g in (s or "").split(",") if g.strip()]

def allowed_by_globs(rel_path: str, allow_globs: List[str], deny_globs: List[str]) -> Tuple[bool, str]:
    for g in deny_globs:
        if fnmatch.fnmatch(rel_path, g): return (False, f"denied by pattern: {g}")
    if allow_globs:
        for g in allow_globs:
            if fnmatch.fnmatch(rel_path, g): return (True, f"allowed by pattern: {g}")
        return (False, "no allowlist pattern matched")
    return (True, "no allowlist; allowed")

# ---------- Pin helpers ----------
def ipfs_add_cli(path: Path) -> Optional[str]:
    ipfs_bin = which("ipfs")
    if not ipfs_bin: return None
    try:
        return subprocess.check_output([ipfs_bin, "add", "-Q", str(path)], text=True).strip() or None
    except Exception:
        return None

def pinata_pin_json(obj: Dict[str, Any], name: str) -> Optional[str]:
    jwt = os.getenv("PINATA_JWT")
    if not jwt: return None
    token = jwt if jwt.startswith("Bearer ") else f"Bearer {jwt}"
    try:
        import urllib.request
        payload = {"pinataOptions": {"cidVersion": 1}, "pinataMetadata": {"name": name}, "pinataContent": obj}
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request("https://api.pinata.cloud/pinning/pinJSONToIPFS", data=data,
                                     headers={"Authorization": token, "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            info = json.loads(resp.read().decode("utf-8") or "{}")
            return info.get("IpfsHash") or info.get("ipfsHash")
    except Exception:
        return None

def maybe_pin_file_or_json(path: Path, obj: Optional[Dict[str, Any]], label: str) -> Tuple[str, str]:
    cid = None
    if path.exists():
        cid = ipfs_add_cli(path)
        if cid: return ("ipfs", cid)
    if obj is not None:
        cid = pinata_pin_json(obj, label)
        if cid: return ("pinata", cid)
    return ("pending", "")

# ---------- Rekor ----------
def rekor_upload_json(path: Path) -> Tuple[bool, Dict[str, Any]]:
    binp = which("rekor-cli")
    rep_sha = sha256_path(path)
    proof_path = OUTDIR / f"rekor_proof_{rep_sha}.json"
    if not binp:
        return (False, {"message": "rekor-cli not found", "proof_path": None})
    try:
        out = subprocess.check_output([binp, "upload", "--artifact", str(path), "--format", "json"],
                                      text=True, stderr=subprocess.STDOUT)
        try:
            data = json.loads(out)
        except Exception:
            data = {"raw": out}
        proof_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        info = {
            "ok": True,
            "uuid": data.get("UUID") or data.get("uuid"),
            "logIndex": data.get("LogIndex") or data.get("logIndex"),
            "proof_path": str(proof_path.relative_to(ROOT)),
            "raw": data
        }
        return (True, info)
    except subprocess.CalledProcessError as e:
        return (False, {"message": (e.output or "").strip(), "proof_path": None})
    except Exception as e:
        return (False, {"message": str(e), "proof_path": None})

# ---------- Validation ----------
def validate_builtin(obj: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(obj, dict): return ["not a JSON object"]
    if not isinstance(obj.get("scroll_name"), str) or not obj.get("scroll_name"):
        errors.append("missing/invalid scroll_name")
    if "status" in obj and not isinstance(obj["status"], str):
        errors.append("status must be string if present")
    cid = obj.get("cid") or obj.get("ipfs_pin")
    if cid and not CID_PATTERN.match(str(cid)):
        errors.append("cid/ipfs_pin does not look like IPFS CID")
    return errors

def validate_with_schema(obj: Dict[str, Any]) -> List[str]:
    if not SCHEMA_PATH.exists(): return []
    try:
        import jsonschema
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = getattr(jsonschema, "Draft202012Validator", jsonschema.Draft7Validator)(schema)
        return [f"{'/'.join([str(p) for p in e.path]) or '<root>'}: {e.message}" for e in validator.iter_errors(obj)]
    except Exception:
        return []

def write_validation_report(results: List[Dict[str, Any]]) -> Path:
    write_json(VALIDATION_PATH, {"timestamp": now_iso(), "results": results})
    return VALIDATION_PATH

# ---------- QR ----------
def emit_cid_qr(cid: Optional[str]) -> Dict[str, Optional[str]]:
    out = {"cid": cid, "png": None, "txt": None}
    if not cid: return out
    txt_path = OUTDIR / f"cid_{cid}.txt"
    txt_path.write_text(f"ipfs://{cid}\nhttps://ipfs.io/ipfs/{cid}\n", encoding="utf-8")
    out["txt"] = str(txt_path.relative_to(ROOT))
    try:
        import qrcode
        img = qrcode.make(f"ipfs://{cid}")
        png_path = OUTDIR / f"cid_{cid}.png"
        img.save(png_path)
        out["png"] = str(png_path.relative_to(ROOT))
    except Exception:
        pass
    return out

# ---------- Glyph ----------
def update_glyph(plan: Dict[str, Any], mode: str, pins: Dict[str, Dict[str, str]], extra: Dict[str, Any]) -> Dict[str, Any]:
    glyph = {
        "scroll_name": "Δ135_TRIGGER",
        "timestamp": now_iso(),
        "initiator": plan.get("initiator", "Matthew Dewayne Porter"),
        "meaning": "Initiate → Expand → Seal",
        "phases": plan.get("phases", ["ΔSCAN_LAUNCH","ΔMESH_BROADCAST_ENGINE","ΔSEAL_ALL"]),
        "summary": {
            "ledger_files": plan.get("summary", {}).get("ledger_files", 0),
            "unresolved_cids": plan.get("summary", {}).get("unresolved_cids", 0)
        },
        "inputs": plan.get("inputs", [])[:50],
        "last_run": {"mode": mode, **extra, "pins": pins}
    }
    write_json(GLYPH_PATH, glyph); return glyph

# ---------- Main ----------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Δ135 auto-executing trigger")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--resolve-missing", action="store_true")
    ap.add_argument("--pin", action="store_true")
    ap.add_argument("--rekor", action="store_true")
    ap.add_argument("--max-bytes", type=int, default=int(os.getenv("RESOLVER_MAX_BYTES", "10485760")))
    # env harmonization
    allow_env = os.getenv("RESOLVER_ALLOW", os.getenv("RESOLVER_ALLOW_GLOB", ""))
    deny_env  = os.getenv("RESOLVER_DENY",  os.getenv("RESOLVER_DENY_GLOB",  ""))
    ap.add_argument("--allow", action="append", default=[g for g in allow_env.split(",") if g.strip()])
    ap.add_argument("--deny",  action="append", default=[g for g in deny_env.split(",")  if g.strip()])
    args = ap.parse_args(argv)

    OUTDIR.mkdir(parents=True, exist_ok=True); LEDGER_DIR.mkdir(parents=True, exist_ok=True)

    # Scan ledger
    scanned: List[Dict[str, Any]] = []
    for p in find_ledger_objects():
        meta = {"path": str(p.relative_to(ROOT)), "size": p.stat().st_size, "mtime": int(p.stat().st_mtime)}
        j = load_json(p)
        if j:
            meta["scroll_name"] = j.get("scroll_name"); meta["status"] = j.get("status")
            meta["cid"] = j.get("cid") or j.get("ipfs_pin") or ""
        scanned.append(meta)

    # Validate
    validation_results: List[Dict[str, Any]] = []
    for item in scanned:
        j = load_json(ROOT / item["path"]) or {}
        errs = validate_with_schema(j) or validate_builtin(j)
        if errs: validation_results.append({"path": item["path"], "errors": errs})
    validation_report_path = write_validation_report(validation_results)

    # unresolved = missing OR invalid CID
    def is_invalid_or_missing(x): 
        c = x.get("cid", "")
        return (not c) or (not CID_PATTERN.match(str(c)))
    unresolved = [s for s in scanned if is_invalid_or_missing(s)]

    plan = {
        "scroll_name": "Δ135_TRIGGER", "timestamp": now_iso(),
        "initiator": os.getenv("GODKEY_IDENTITY", "Matthew Dewayne Porter"),
        "phases": ["ΔSCAN_LAUNCH", "ΔMESH_BROADCAST_ENGINE", "ΔSEAL_ALL"],
        "summary": {"ledger_files": len(scanned), "unresolved_cids": len(unresolved)},
        "inputs": scanned
    }
    write_json(TRIGGER_PATH, plan)

    if args.dry_run or (not args.execute):
        write_json(REPORT_PATH, {
            "timestamp": now_iso(), "mode": "plan",
            "plan_path": str(TRIGGER_PATH.relative_to(ROOT)),
            "plan_sha256": sha256_path(TRIGGER_PATH),
            "validation_report": str(validation_report_path.relative_to(ROOT)),
            "result": {"message": "Δ135 planning only (no actions executed)"}
        })
        update_glyph(plan, mode="plan", pins={}, extra={
            "report_path": str(REPORT_PATH.relative_to(ROOT)),
            "report_sha256": sha256_path(REPORT_PATH),
            "mesh_event_path": None,
            "qr": {"cid": None}
        })
        print(f"[Δ135] Planned. Ledger files={len(scanned)} unresolved_cids={len(unresolved)}")
        return 0

    # Resolve (auto-repin) with guardrails; write-back scroll JSON on success
    cid_resolution: List[Dict[str, Any]] = []
    if args.resolve_missing and unresolved:
        allow_globs = [g for sub in (args.allow or []) for g in (split_globs(sub) or [""]) if g]
        deny_globs  = [g for sub in (args.deny  or []) for g in (split_globs(sub) or [""]) if g]
        for item in list(unresolved):
            rel = item["path"]; ledger_path = ROOT / rel
            # guardrails
            ok, reason = allowed_by_globs(rel, allow_globs, deny_globs)
            if not ok:
                cid_resolution.append({"path": rel, "action": "skip", "reason": reason}); continue
            if (not ledger_path.exists()) or (ledger_path.stat().st_size > args.max_bytes):
                cid_resolution.append({"path": rel, "action": "skip", "reason": f"exceeds max-bytes ({args.max_bytes}) or missing"}); continue
            # pin flow
            j = load_json(ledger_path) or {}
            prev = j.get("cid")
            mode, cid = maybe_pin_file_or_json(ledger_path, j, f"ΔLEDGER::{ledger_path.name}")
            if cid:
                j["cid"] = cid  # write back
                try: ledger_path.write_text(json.dumps(j, ensure_ascii=False, indent=2), encoding="utf-8")
                except Exception: pass
                item["cid"] = cid
                cid_resolution.append({"path": rel, "action": "repinned", "mode": mode, "prev": prev, "cid": cid})
        # recompute unresolved
        unresolved = [s for s in scanned if (not s.get("cid")) or (not CID_PATTERN.match(str(s.get("cid",""))))]
        plan["summary"]["unresolved_cids"] = len(unresolved)
        write_json(TRIGGER_PATH, plan)

    # Mesh event
    affected = [{"path": i["path"], "cid": i.get("cid", ""), "scroll_name": i.get("scroll_name")} for i in scanned]
    event = {"event_name": "ΔMESH_EVENT_135", "timestamp": now_iso(), "trigger": "Δ135",
             "affected": affected, "actions": ["ΔSCAN_LAUNCH","ΔMESH_BROADCAST_ENGINE","ΔSEAL_ALL"]}
    write_json(MESH_EVENT_PATH, event)

    pins: Dict[str, Dict[str, str]] = {}
    if args.pin:
        mode, ident = maybe_pin_file_or_json(TRIGGER_PATH, plan, "Δ135_TRIGGER")
        pins["Δ135_TRIGGER"] = {"mode": mode, "id": ident}

    # Best CID + QR
    best_cid = pins.get("Δ135_REPORT", {}).get("id") if pins else None
    if not best_cid: best_cid = pins.get("Δ135_TRIGGER", {}).get("id") if pins else None
    if not best_cid:
        for s in scanned:
            if s.get("cid"): best_cid = s["cid"]; break
    qr = emit_cid_qr(best_cid)

    # Report
    result = {"timestamp": now_iso(), "mode": "execute",
              "mesh_event_path": str(MESH_EVENT_PATH.relative_to(ROOT)),
              "mesh_event_hash": sha256_path(MESH_EVENT_PATH)}
    report = {"timestamp": now_iso(), "plan": plan, "event": event, "result": result,
              "pins": pins, "cid_resolution": cid_resolution,
              "validation_report": str(validation_report_path.relative_to(ROOT)), "qr": qr}
    write_json(REPORT_PATH, report)

    # Rekor sealing (optional)
    if args.rekor:
        ok, info = rekor_upload_json(REPORT_PATH)
        report["rekor"] = {"ok": ok, **info}
        write_json(REPORT_PATH, report)

    # Pin the report (optional, after Rekor for stable hash capture)
    if args.pin:
        rep_obj = load_json(REPORT_PATH)
        mode, ident = maybe_pin_file_or_json(REPORT_PATH, rep_obj, "Δ135_REPORT")
        pins["Δ135_REPORT"] = {"mode": mode, "id": ident}
        report["pins"] = pins; write_json(REPORT_PATH, report)

    # Glyph
    extra = {"report_path": str(REPORT_PATH.relative_to(ROOT)),
             "report_sha256": sha256_path(REPORT_PATH),
             "mesh_event_path": str(MESH_EVENT_PATH.relative_to(ROOT)),
             "qr": qr}
    if report.get("rekor", {}).get("proof_path"):
        extra["rekor_proof"] = report["rekor"]["proof_path"]
        extra["rekor_uuid"] = report["rekor"].get("uuid")
        extra["rekor_logIndex"] = report["rekor"].get("logIndex")
    update_glyph(plan, mode="execute", pins=pins, extra=extra)

    print(f"[Δ135] Executed. Mesh event → {MESH_EVENT_PATH.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
''').strip("\n")

(SCRIPTS / "Δ135_TRIGGER.py").write_text(trigger, encoding="utf-8")

# --- (2) Dashboard patch: Rekor panel + pinning matrix ---
tile = textwrap.dedent(r'''
import json, os, subprocess
from pathlib import Path
import streamlit as st

ROOT = Path.cwd()
OUTDIR = ROOT / "truthlock" / "out"
GLYPH = OUTDIR / "Δ135_GLYPH.json"
REPORT = OUTDIR / "Δ135_REPORT.json"
TRIGGER = OUTDIR / "Δ135_TRIGGER.json"
EVENT = OUTDIR / "ΔMESH_EVENT_135.json"
VALID = OUTDIR / "ΔLEDGER_VALIDATION.json"

def load_json(p: Path):
    try: return json.loads(p.read_text(encoding="utf-8"))
    except Exception: return {}

st.title("Δ135 — Auto-Repin + Rekor")
st.caption("Initiate → Expand → Seal  •  ΔSCAN_LAUNCH → ΔMESH_BROADCAST_ENGINE → ΔSEAL_ALL")

glyph = load_json(GLYPH)
report = load_json(REPORT)
plan = load_json(TRIGGER)
validation = load_json(VALID)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Ledger files", plan.get("summary", {}).get("ledger_files", 0))
c2.metric("Unresolved CIDs", plan.get("summary", {}).get("unresolved_cids", 0))
c3.metric("Last run", (glyph.get("last_run", {}) or {}).get("mode", (report or {}).get("mode", "—")))
c4.metric("Timestamp", glyph.get("timestamp", "—"))

issues = validation.get("results", [])
if isinstance(issues, list) and len(issues) == 0:
    st.success("Ledger validation: clean ✅")
else:
    st.error(f"Ledger validation: {len(issues)} issue(s) ❗")
    with st.expander("Validation details"): st.json(issues)

with st.expander("Guardrails (env)"):
    st.write("**Max bytes:**", os.getenv("RESOLVER_MAX_BYTES", "10485760"))
    st.write("**Allow globs:**", os.getenv("RESOLVER_ALLOW", os.getenv("RESOLVER_ALLOW_GLOB", "")) or "—")
    st.write("**Deny globs:**",  os.getenv("RESOLVER_DENY",  os.getenv("RESOLVER_DENY_GLOB",  "")) or "—")

st.write("---")
st.subheader("Rekor Transparency")
rk = (report or {}).get("rekor", {})
if rk.get("ok"):
    st.success("Rekor sealed ✅")
    st.write("UUID:", rk.get("uuid") or "—")
    st.write("Log index:", rk.get("logIndex") or "—")
    if rk.get("proof_path"):
        proof = ROOT / rk["proof_path"]
        if proof.exists():
            st.download_button("Download Rekor proof", proof.read_bytes(), file_name=proof.name)
else:
    st.info(rk.get("message") or "Not sealed (run with --rekor)")

st.write("---")
st.subheader("Pinning Matrix")
rows = []
for r in (report.get("cid_resolution") or []):
    rows.append({"path": r.get("path"), "action": r.get("action"), "mode": r.get("mode"),
                 "cid": r.get("cid"), "reason": r.get("reason")})
if rows:
    st.dataframe(rows, hide_index=True)
else:
    st.caption("No CID resolution activity in last run.")

st.write("---")
st.subheader("Run Controls")
with st.form("run135"):
    a,b,c,d = st.columns(4)
    execute = a.checkbox("Execute", True)
    resolve = b.checkbox("Resolve missing", True)
    pin     = c.checkbox("Pin artifacts", True)
    rekor   = d.checkbox("Rekor upload", True)
    max_bytes = st.number_input("Max bytes", value=int(os.getenv("RESOLVER_MAX_BYTES","10485760")), min_value=0, step=1_048_576)
    allow = st.text_input("Allow globs (comma-separated)", value=os.getenv("RESOLVER_ALLOW", os.getenv("RESOLVER_ALLOW_GLOB","")))
    deny  = st.text_input("Deny globs (comma-separated)",  value=os.getenv("RESOLVER_DENY",  os.getenv("RESOLVER_DENY_GLOB","")))
    go = st.form_submit_button("Run Δ135")
    if go:
        args = []
        if execute: args += ["--execute"]
        else: args += ["--dry-run"]
        if resolve: args += ["--resolve-missing"]
        if pin: args += ["--pin"]
        if rekor: args += ["--rekor"]
        args += ["--max-bytes", str(int(max_bytes))]
        if allow.strip():
            for a1 in allow.split(","):
                a1=a1.strip()
                if a1: args += ["--allow", a1]
        if deny.strip():
            for d1 in deny.split(","):
                d1=d1.strip()
                if d1: args += ["--deny", d1]
        subprocess.call(["python", "truthlock/scripts/Δ135_TRIGGER.py", *args])
        st.experimental_rerun()

st.write("---")
st.subheader("Latest CID & QR")
qr = (glyph.get("last_run", {}) or {}).get("qr") or (report or {}).get("qr") or {}
if qr.get("cid"):
    st.write(f"CID: `{qr['cid']}`")
    png = OUTDIR / f"cid_{qr['cid']}.png"
    txt = OUTDIR / f"cid_{qr['cid']}.txt"
    if png.exists():
        st.image(str(png), caption=f"QR for ipfs://{qr['cid']}")
        st.download_button("Download QR PNG", png.read_bytes(), file_name=png.name)
    if txt.exists():
        st.download_button("Download QR TXT", txt.read_bytes(), file_name=txt.name)
else:
    st.caption("No CID yet.")

st.write("---")
st.subheader("Artifacts")
cols = st.columns(4)
if TRIGGER.exists(): cols[0].download_button("Δ135_TRIGGER.json", TRIGGER.read_bytes(), file_name="Δ135_TRIGGER.json")
if REPORT.exists():  cols[1].download_button("Δ135_REPORT.json",  REPORT.read_bytes(),  file_name="Δ135_REPORT.json")
if EVENT.exists():   cols[2].download_button("ΔMESH_EVENT_135.json", EVENT.read_bytes(), file_name="ΔMESH_EVENT_135.json")
if VALID.exists():   cols[3].download_button("ΔLEDGER_VALIDATION.json", VALID.read_bytes(), file_name="ΔLEDGER_VALIDATION.json")
''').strip("\n")

(GUI / "Δ135_tile.py").write_text(tile, encoding="utf-8")

# --- (3) Execute sealed run (uses env if present) ---
def run(cmd): 
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

rc, out, err = run([
    "python", str(SCRIPTS / "Δ135_TRIGGER.py"),
    "--execute", "--resolve-missing", "--pin", "--rekor",
    "--max-bytes", "10485760", "--allow", "truthlock/out/ΔLEDGER/*.json"
])

# Write a tiny summary for quick inspection
summary = {
    "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "rc": rc, "stdout": out, "stderr": err,
    "artifacts": sorted(p.name for p in OUT.iterdir())
}
(OUT / "Δ135_RKR_SUMMARY.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False))ΔCASE_BUILDER_TX: Texas Case Pack Kit Overview

The ΔCASE_BUILDER_TX kit is a customizable, spreadsheet-based toolkit for building and managing legal case files in Texas, especially for local disputes (“around-town” matters) and family law cases. It’s not legal advice – rather, it provides a structured “scaffold” to track facts, evidence, witnesses, and legal theories over time, helping you stay organized and clear on what needs to be proven in each claim.  The kit uses linked templates (CSV files and Markdown drafts) so that events, documents, and claims are all cross-referenced. For example, timeline entries reference evidence IDs, and legal-claim matrices tie facts to specific legal elements. This approach mirrors best practices in litigation preparation, where each fact and piece of evidence is linked to the issues it supports. As facts or documents emerge (e.g. via public records requests), you update the timeline and evidence logs, which in turn refines your legal strategy and drafting.

Kit Structure and Contents

The kit is organized into folders and files as follows:

README.md: A quick-start guide (explaining the kit’s purpose and usage).

00_index.csv: A master index spreadsheet listing all cases (columns: slug, case title, jurisdiction, etc.). This serves as a table of contents for your matters. (The example kit seeds one row: wise-cv19-04-307-1, “Wise County family matter – set-aside/modify”, etc.)

templates/: This folder contains structured templates (mostly CSVs and text files) to be copied or filled in for each case. Key templates include:

01_timeline.csv: Chronological events with columns like Date, Event, Who, Source/Proof, Impact, Next Action. Each row is a fact or event you want to track. This is essentially a formal case chronology.  Legal teams often use timelines to organize facts by date and link them to issues or evidence.

02_evidence_index.csv: An exhibit log. Each row is an evidence item (document, photo, transcript, etc.) with ID, description, storage location, SHA-256 hash, provenance, and linked legal claims. Using unique IDs and hashes helps preserve chain-of-custody and verify integrity of files. (For example, hashing digital evidence and logging it is a standard practice to ensure data hasn’t been altered.) The Linked Elements column ties each exhibit to the claims or legal elements it supports.

03_witness_list.csv: Details of witnesses: name, role (e.g. neighbor, teacher), contact info, what they know, risk/retaliation concerns, and notes. This helps plan depositions or declarations.

04_event_log.csv: A detailed incident log (timestamp, actor, action, location, link, notes). This is useful for real-time tracking of interactions (e.g., police encounters, agency contacts) beyond the major “events” in the timeline.

05_public_info_requests/TPRA_request_template.txt: A draft Texas Public Information Act (TPIA) letter. Texas law (Gov’t Code Ch. 552) guarantees citizens access to most government records. The template covers the required format for a records request (subject, time frame, records sought) and notes deadlines. You can customize and send it to government agencies (city police, school district, DFPS, etc.) to gather official documents (e.g. police reports, school discipline records).

06_legal_theories_matrix.csv: A “proof matrix” chart. Each row is a legal claim or theory (e.g. Modify SAPCR order, 42 U.S.C. §1983 due process claim, etc.) with columns for required elements, supporting facts/evidence (linked by timeline and evidence IDs), current status, and forum (court or agency). This helps ensure you’ve considered each element of each claim and identifies any evidentiary gaps. (In essence, this is similar to an “order of proof” or fact matrix used in complex cases – linking facts to legal elements.)

07_drafts/: Markdown templates for drafting pleadings in each case. Current examples include:

complaint_1983.md – A federal §1983 civil-rights complaint (for constitutional claims against state actors). This outlines party names, jurisdiction, facts (linked to evidence), legal claims (e.g. due process violations, Monell claim, etc.), and requested relief. 42 U.S.C. §1983 provides that anyone acting under “color of” state law who deprives another of constitutional rights is liable.

petition_modify_SAPCR.md – Petition to modify a prior custody or support order in a Suit Affecting the Parent-Child Relationship (SAPCR).  (In Texas family law, SAPCR is the term for cases involving custody, visitation, and support.) This template helps state the facts and grounds for modification (such as material change in circumstances) in the court that issued the original order.

petition_bill_of_review.md – Petition for bill of review (an equitable petition to set aside a judgment long after appeals have closed). A Texas bill of review lets a party challenge a final order if a valid defense was denied by fraud or mistake. The template includes elements like petitioner’s meritorious defense, how fraud/accident prevented trial, and lack of petitioner’s fault.

motion_to_recuse.md – Motion asking the judge to recuse (step aside) due to bias or conflict. Texas law (Rule 18b) requires a verified motion with specific allegations of bias or interest. For example, the motion must state facts showing the judge has personal bias or a conflict of interest.


08_external_complaints/: Markdown templates for administrative complaints outside the court process. Examples include:

judicial_misconduct_complaint.md – Complaint to the Texas State Commission on Judicial Conduct. Texas judges suspected of misconduct can be reported to the Commission. (The Commission requires a sworn complaint form sent by mail.)

OAG_child_support_complaint.md – Complaint to the Texas Attorney General’s Child Support Division. If the state child-support agency mishandles your case, you can file a complaint with the OAG (which has a standard complaint form).

DFPS_grievance.md – Grievance to Texas DFPS (CPS) via the Office of Consumer Affairs. For issues in a child welfare case, DFPS provides a Case Complaint Form.




Each template has placeholders and instructions, so you copy it (or the whole templates folder) into your case folder and replace fields with your facts. Together these pieces ensure no detail is overlooked: timelines drive the narrative, evidence logs secure proof, the legal matrix maps to laws, and draft forms get you writing.

Getting Started with a New Case

1. Create a case record. Duplicate case.example.json as case.<your-slug>.json (e.g. case.jones-divorce.json) and edit the metadata (slug, title, jurisdiction, case number, parties, etc.). This JSON ties the case to the template files. Also add a row to 00_index.csv for this case (listing slug, title, jurisdiction, case type, status, notes). This index is your table of contents for multiple matters.


2. Populate the timeline. Open templates/01_timeline.csv and start entering chronological events relevant to your case. Include dates, event descriptions, involved persons (“who”), the source or proof of the event (e.g. “Police report [E05]”), the impact, and any next steps. Always link to evidence IDs in 02_evidence_index.csv (see below) to support each fact. For example:

2021-06-01 – Child support hearing; Judge Smith grants temporary order. (source: hearing transcript [E10]).

2022-01-15 – Child discloses abuse to teacher Ms. Lee. (source: teacher affidavit [E15]).
Chronologies like this help organize facts into a story. Lawyers often advise “to build a timeline of facts and link them to issues” for clarity. Regularly update this as new events happen.



3. Log all evidence. Use templates/02_evidence_index.csv to record each piece of evidence. Assign each exhibit an ID (E01, E02, …). Include a brief description, where it’s stored, and a SHA-256 hash of the file (for digital evidence, a hash helps prove it hasn’t been tampered). Note the provenance (e.g. source) and link it to legal elements in the matrix. For example:

E01: Police report (2019) – /evidence/police_report_2019.pdf – [hash] – Sergeant Jones – Supports parental unfitness claim.

E02: Text message screenshot – /evidence/text_2021-08-15.png – [hash] – Sender: Co-parent – Supports timeline event of argument.
Each timeline entry’s “Source/Proof” should refer to an Exhibit ID here. This cross-linking makes it easy to cite proof in pleadings (e.g. “see Exh. E02”).



4. Build your witness list. Fill in templates/03_witness_list.csv with anyone who can testify or provide evidence: family members, teachers, neighbors, professionals, etc. For each, note their role (e.g. “medical expert”, “mom’s friend”), contact info, what facts they know, and any concerns (risk of retaliation, reliability). A witness list keeps track of testimony you may need to collect (affidavits, depositions).


5. Track daily events. Use templates/04_event_log.csv for a running log of detailed incidents or interactions (date/time, actor, action, location, link to any note or document, plus free-form notes). This is especially useful for things like documenting police encounters, school meetings, or other incidents that happen on the fly. Think of it like an incident report log – it ensures no detail is forgotten.


6. Submit public records requests. The kit’s 05_public_info_requests/TPRA_request_template.txt is a draft letter you can adapt and send to local agencies under the Texas Public Information Act. The TPIA (Tex. Gov’t Code Ch. 552) states “each person is entitled…at all times to complete information about the affairs of government”. In practice, that means you can ask for records like arrest reports, case notes, personnel files, etc.  Editing this template with the correct agency name, your case details, and desired date range can uncover valuable evidence (e.g. school emails, police logs, DFPS records). Government bodies must respond (or validly withhold) within deadlines set by the Act.


7. Define your legal claims. In 06_legal_theories_matrix.csv, list every claim or theory you’re considering: e.g. “SAPCR modification (conservatorship)”, “Bill of Review – set aside judgment”, “42 U.S.C. §1983 due process”, “§1983 Monell (municipal liability)”, etc. For each, write out the elements required by law (you’ll find these in statutes or case law) and then, in a column, note which timeline facts or evidence support each element. Also track the current status (“drafting”, “researching”, “filed”, etc.) and in what forum it goes (e.g. “District Court – Family Division”). This matrix serves as a litigation checklist, revealing “gaps” where you lack proof. For example, a §1983 claim requires showing a state actor deprived someone of a constitutional right; you’d link each alleged constitutional violation to your evidence.


8. Draft pleadings. For each claim, copy the appropriate template from 07_drafts/. For example:

If pursuing a civil rights claim, edit complaint_1983.md, inserting your parties and facts (drawn from the timeline/evidence).

For custody changes, edit petition_modify_SAPCR.md, describing the existing order, why circumstances changed, and why modification serves the child’s best interest (Texas family courts require showing a material and substantial change since the last order).

To attack an old judgment, use petition_bill_of_review.md, laying out how fraud or mistake denied you a fair trial (Texas bills of review require a meritorious defense that was thwarted by fraud or accident).

If you need to recuse a judge, fill motion_to_recuse.md with the specific facts of bias or conflict (remember: the motion must be verified and state detailed facts, not just the judge’s rulings).
The Markdown format makes editing easy. Be sure to link your citations: e.g., “[E01]” for evidence, or cite statutes/law when mentioning legal standards.



9. Handle external issues. If you uncover misconduct by officials (judges, CPS workers, etc.), use the 08_external_complaints/ templates:

Judicial Misconduct: To file a complaint about a judge, you generally submit a sworn form to the Texas State Commission on Judicial Conduct. The template helps you tell your story according to their rules.

Child Support Complaints: The Texas Attorney General’s Child Support Division has a complaint process (see OAG’s child support complaint form). The template organizes your issues (e.g. failure to enforce, misinformation).

DFPS Grievances: For problems with CPS (DFPS), the DFPS Office of Consumer Affairs provides a case complaint form. The kit’s template helps fill out key information needed for that.



10. Maintain and iterate. As your case progresses – hearings, discovery, new evidence – update the timeline, evidence log, and matrix. That in turn informs any revisions to your drafts. For instance, after receiving discovery, add new exhibits to 02_evidence_index.csv and reference them in 01_timeline.csv. Cross-references keep your work synchronized: each piece of evidence has a home and a purpose.  This creates a feedback loop: organizing facts clarifies your legal approach, which clarifies what documents and testimony you need next.



Key Templates Explained

00_index.csv: Think of this as your case database. Each row is one case/matter. Columns include slug (a unique identifier), case title, jurisdiction, case type (e.g. Family, Civil), current status, and notes. Update it whenever you start a new case or change status (e.g. “filed,” “settled,” “trial”).

01_timeline.csv: Records every significant event (court filings, hearings, incidents, communications) in chronological order. For each event, note: Date (YYYY-MM-DD), Event description, Who was involved, Source/proof (cite document or witness, e.g. “[E05]” for an exhibit), Impact (how it affected the case), and Next Action (what to do next).  Lawyers emphasize the importance of timelines: they let you see the case narrative at a glance and ensure no fact is missed. As you fill this out, link to the evidence log by putting exhibit IDs in the Source column.

02_evidence_index.csv: Each piece of evidence gets a unique ID (E01, E02, …). Columns include Description, Storage Location (folder path or physical location), SHA-256 Hash, Provenance (who provided it), and Linked Elements. Recording a hash of digital evidence is a best practice for integrity. In Linked Elements, note which claims or issues this evidence supports (matching the legal matrix). This index helps you track what you have (files) and how it ties to your story.

03_witness_list.csv: Track all potential witnesses. For each person, record their contact info, how they know the facts (knowledge), and any risk factors (e.g. retaliation or credibility issues). Having a clear witness plan is critical, especially in custody cases where many people (family, teachers, doctors) may testify.

04_event_log.csv: Use this for a running log of granular details (time-stamped). For example, if you speak to a judge or police officer, note the date/time, person, action, location, and any result. This is like keeping a diary of case-related events, which can be helpful if facts become disputed.

05_public_info_requests/TPRA_request_template.txt: The Texas Public Information Act (TPIA) encourages transparency. This template is a generic letter to ask for records. It reminds agencies of their duty to provide records (or justify withholding them). By sending tailored TPIA requests (e.g. to the sheriff’s office, school district, DFPS), you may uncover evidence (like police dispatch logs or child welfare reports) that otherwise are hard to get. Note deadlines: agencies must respond within 10 business days (plus extensions) per state law.

06_legal_theories_matrix.csv: This is a strategic tool. List each Claim/Theory (e.g. “Family law – Modify Custody Order”, “Federal §1983 – Due Process”, “State Law – Defamation”, etc.), then in the Elements column write out each element you must prove (e.g. for custody modification: “material and substantial change” + “child’s best interest”). In Supporting Facts/Evidence, fill in which timeline facts or exhibits satisfy those elements. Also note Current Status (e.g. “drafting”, “disputed”), and Forum (e.g. “State District Court – Family”). This matrix is akin to a proof chart used by litigators to ensure every element has evidence, and it highlights where more investigation is needed.

07_drafts/… .md: These are the skeletal pleadings and motions. They’re written in Markdown so you can edit them easily. You should copy a template and then customize it. For instance:

complaint_1983.md: Outline a 42 U.S.C. §1983 lawsuit. (Section 1983 allows suing state actors who violate constitutional rights.) The template includes sections for parties, jurisdiction, facts (with brackets where you insert your timeline entries), and claims (e.g. “Violation of due process under the Fourteenth Amendment”). You’d fill in names, dates, and facts from your timeline, citing exhibits as needed (e.g. “see Exh. E07 – school records”).

petition_modify_SAPCR.md: Use this to request custody/support modification. It guides you to state the prior order, facts since then, the material change, and why the change serves the child’s best interest. Texas Family Code requires this showing for modification.

petition_bill_of_review.md: If you need to challenge an old family court judgment (e.g. if fraud prevented your proper notice), this petition seeks relief by equitable bill of review. It prompts for the three elements (meritorious defense, fraud/accident/official mistake prevented trial, and no fault by petitioner).

motion_to_recuse.md: This template helps structure a motion asking the court to replace the judge. It reminds you that the motion must be verified and detailed (simply criticizing rulings isn’t enough). You’d insert the specific facts (e.g. “Judge X is the cousin of the other party” or “Judge X expressed prejudice against us, as noted in [filing/record]”).


08_external_complaints/: These templates are for parallel administrative remedies, in case there’s misconduct outside the courts. For example:

judicial_misconduct_complaint.md: Addresses improper behavior by a judge. Texas’s independent Commission on Judicial Conduct takes sworn complaints about judicial misconduct. (By law, you must use their official form, but this template helps you draft the narrative.)

OAG_child_support_complaint.md: The Texas Attorney General’s Child Support Division encourages parents to report issues via their online system or by mail. This template mirrors the information that OAG’s complaint form asks for. (For example, OAG provides a Complaint Form PDF.) You would summarize your child support enforcement problem and attach relevant documents.

DFPS_grievance.md: DFPS’s Office of Consumer Affairs handles case-specific complaints. The DFPS Case Complaint Form (Form N-509-0101, 2024) lets you allege that DFPS staff violated policy in your case. The template guides you through the required fields (your info, case identifiers, what went wrong). You can then email, fax, or mail it to DFPS as instructed.



Example Starter Case

The kit includes case.example.json, pre-filled with a sample Wise County family case (CV19-04-307-1). It has fields like slug, title, jurisdiction, case number, and links to the template files. You should use this as a model: copy it to create case.<your-slug>.json for each new matter. Then edit its contents for your facts. The JSON format also makes it possible to automate parts of the process (e.g. a script could read the JSON and open the right files).  For instance, the example shows "jurisdiction": "Wise County, TX", "case_number": "CV19-04-307-1", tying it to that specific court file.

How to Use the Kit (Workflow Summary)

1. Set Up: Clone or unzip the kit to your computer. Read README.md for an overview.


2. Create Case File: Make a new case JSON (or update the index) for your matter.


3. Collect Facts: Fill 01_timeline.csv with all relevant events (start from earliest). Log evidence in 02_evidence_index.csv concurrently. Always cite proof for each fact.


4. Send Records Requests: Customize the TPRA template to seek government records that can corroborate your facts (e.g. police reports, school records, medical logs).


5. Chart Legal Issues: In the legal theories matrix, list each potential claim and link the facts/evidence to its elements. This clarifies which claims are viable and what proof is missing.


6. Draft Papers: For each claim you pursue, copy the matching Markdown draft and tailor it with your facts. Reference timeline entries and evidence (e.g. “On 2021-06-01, the court ordered X”).


7. Parallel Remedies: If you identify misconduct (judicial bias, falsified records, CPS errors, etc.), use the external complaint templates to file appropriate grievances. These do not replace court action but may apply pressure or trigger investigations.


8. Update Continuously: As new events happen or new evidence arrives, update the timeline, evidence log, and matrix. Revise your drafts if needed. This “build loop” keeps your case materials cohesive and up-to-date.



By following this organized approach, you build a complete file of your case: a narrative timeline with linked proof, a clear map of legal claims, and ready-to-edit pleadings. This makes it easier to collaborate with an attorney (who can review these files) or to self-manage your case preparation. All key information is interlinked, so the end result is a coherent, evidence-backed case presentation.

Disclaimer: This kit is a tool, not legal advice. Always consult a qualified Texas attorney before filing any court documents. Use secure methods (like hashing) for sensitive files. The name “Δ” (delta) signals focus on change: identify changes in circumstances (for family law) and changes to pursue legally. With disciplined use of these templates and ongoing research, you can construct a strong, well-documented case ready for your lawyer’s review.

# codex-universal

`codex-universal` is a reference implementation of the base Docker image available in [OpenAI Codex](http://platform.openai.com/docs/codex).

This repository is intended to help developers cutomize environments in Codex, by providing a similar image that can be pulled and run locally. This is not an identical environment but should help for debugging and development.

For more details on environment setup, see [OpenAI Codex](http://platform.openai.com/docs/codex).

## Usage

The Docker image is available at:

```
docker pull ghcr.io/openai/codex-universal:latest
```

The below script shows how can you approximate the `setup` environment in Codex:

```sh
# See below for environment variable options.
# This script mounts the current directory similar to how it would get cloned in.
docker run --rm -it \
    -e CODEX_ENV_PYTHON_VERSION=3.12 \
    -e CODEX_ENV_NODE_VERSION=20 \
    -e CODEX_ENV_RUST_VERSION=1.87.0 \
    -e CODEX_ENV_GO_VERSION=1.23.8 \
    -e CODEX_ENV_SWIFT_VERSION=6.1 \
    -v $(pwd):/workspace/$(basename $(pwd)) -w /workspace/$(basename $(pwd)) \
    ghcr.io/openai/codex-universal:latest
```

`codex-universal` includes setup scripts that look for `CODEX_ENV_*` environment variables and configures the language version accordingly.

### Configuring language runtimes

The following environment variables can be set to configure runtime installation. Note that a limited subset of versions are supported (indicated in the table below):

| Environment variable       | Description                | Supported versions                               | Additional packages                                                  |
| -------------------------- | -------------------------- | ------------------------------------------------ | -------------------------------------------------------------------- |
| `CODEX_ENV_PYTHON_VERSION` | Python version to install  | `3.10`, `3.11.12`, `3.12`, `3.13`                | `pyenv`, `poetry`, `uv`, `ruff`, `black`, `mypy`, `pyright`, `isort` |
| `CODEX_ENV_NODE_VERSION`   | Node.js version to install | `18`, `20`, `22`                                 | `corepack`, `yarn`, `pnpm`, `npm`                                    |
| `CODEX_ENV_RUST_VERSION`   | Rust version to install    | `1.83.0`, `1.84.1`, `1.85.1`, `1.86.0`, `1.87.0` |                                                                      |
| `CODEX_ENV_GO_VERSION`     | Go version to install      | `1.22.12`, `1.23.8`, `1.24.3`                    |                                                                      |
| `CODEX_ENV_SWIFT_VERSION`  | Swift version to install   | `5.10`, `6.1`                                    |                                                                      |

## What's included

In addition to the packages specified in the table above, the following packages are also installed:

- `ruby`: 3.2.3
- `bun`: 1.2.10
- `java`: 21
- `bazelisk` / `bazel`

See [Dockerfile](Dockerfile) for the full details of installed packages.
