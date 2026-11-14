import io
import json
import re
import sys
import time
import zipfile
from datetime import datetime
from itertools import combinations
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

# ==================================================
# SCORE_RUNS HELPERS (from score_runs.py)
# needs prompt_structure.py in the same folder as app.py
# ==================================================
sys.path.insert(0, str(Path(__file__).parent))
from prompt_structre import walk  # noqa: E402

FEASIBILITY = ["elapsedTime", "specialistExpertise", "knowledge", "opportunity", "equipment"]
# ordinal scales, easiest for the attacker first (index = rating code)
SCALES = {"elapsedTime": ["1D", "1W", "1M", "6M", "6M+"],
          "specialistExpertise": ["layman", "proficient", "expert", "multipleExpert"],
          "knowledge": ["public", "restricted", "confidential", "strictlyConfidential"],
          "opportunity": ["unlimited", "easy", "moderate", "difficult"],
          "equipment": ["standard", "specialized", "bespoke", "multipleBespoke"]}
LINKS = ["damages", "sites", "interfaces"]
CIA = ["confidentiality", "integrity", "availability"]
ASSET_TYPES = {"hardware", "software", "data", "functions", "signals"}
HEX_ID = re.compile(r"\b[0-9a-f]{24}\b")
ENUM_WORDS = re.compile(r"entityId|attackStep|attack_step|stepIds|attackPath", re.I)
ABBREV = re.compile(r"\b[A-Z][A-Za-z]*[A-Z]+[A-Za-z]*\b")


def norm(s):
    """Text for 'was it changed?' checks: non-breaking hyphens and spacing don't count."""
    return " ".join(str(s or "").replace("‑", "-").split())


# ---------- prompt parsing ----------

def load_prompt(path):
    return load_prompt_text(open(path, encoding="utf-8").read())


def load_prompt_text(text):
    """Same as load_prompt, but takes the XML text itself (e.g. from an uploaded file)."""
    lines = text.split("\n")
    ids_by_type, example_ids = {}, set()
    for depth, name, start, end, chars, el_path in walk(text):
        if name != "_entityId" or start != end:
            continue
        m = HEX_ID.search(lines[start - 1])
        if not m:
            continue
        parts = el_path.split("/")
        if "relevant_examples" in parts:
            example_ids.add(m.group())
        elif "task_specific_context" in parts:
            # category = first element below the document root, e.g. hardware, damages
            for root in ("itemDefinition", "cybersecurityPlan", "concept", "current_risk_assessment"):
                if root in parts:
                    idx = len(parts) - 1 - parts[::-1].index(root)
                    ids_by_type.setdefault(parts[idx + 1], set()).add(m.group())
                    break
    schema_text = re.search(r"<response_format>(.*?)</response_format>", text, re.S).group(1)
    ra = text[text.find("<current_risk_assessment><current_risk_assessment>"):]
    threats_xml = ra[ra.find("<threats>"):ra.find("</threats>")]
    threats = [parse_threat(b) for b in re.findall(r"<threat>(.*?)</threat>", threats_xml, re.S)]
    vocab = set(re.findall(r"[a-z]+", text.lower()))
    ctx = text[text.find("<task_specific_context>"):text.find("</task_specific_context>")]
    step_codes = {}
    for b in re.findall(r"<attack_step>(.*?)</attack_step>", ctx, re.S):
        sid = re.search(r"<_entityId>([0-9a-f]{24})</_entityId>", b)
        if sid:
            step_codes[sid.group(1)] = rating_codes({f: (re.search(rf"<{f}>(.*?)</{f}>", b) or [None, ""])[1]
                                                     for f in FEASIBILITY})
    return ids_by_type, example_ids, json.loads(schema_text), threats, vocab, step_codes


def parse_threat(block):
    get = lambda tag: (re.search(rf"<{tag}>(.*?)</{tag}>", block, re.S) or [None, ""])[1].strip()
    t = {"_entityId": get("_entityId"), "name": get("name"), "description": get("description"),
         "rationale": get("rationale"), "status": re.search(r"<status>\s*<status>(\w+)", block).group(1)}
    for f in FEASIBILITY:
        t[f] = get(f)
    for f in LINKS:
        t[f] = set(re.findall(rf"<{f}>([0-9a-f]{{24}})</{f}>", block))
    assets = re.search(r"<assets>(.*?)</assets>", block, re.S)
    t["assets"] = {c: set(re.findall(rf"<{c}>([0-9a-f]{{24}})</{c}>", assets.group(1))) if assets else set()
                   for c in CIA}
    t["steps"] = set(re.findall(r"<attack_steps>([0-9a-f]{24})</attack_steps>", block))
    t["paths"] = [re.findall(r"<attack_steps>([0-9a-f]{24})</attack_steps>", p)
                  for p in re.findall(r"<attackPaths>(.*?)</attackPaths>", block, re.S)]
    return t


def rating_codes(t):
    """One code per feasibility attribute (0 = easiest for the attacker); None if not a valid value."""
    return [SCALES[f].index(t.get(f)) if t.get(f) in SCALES[f] else None for f in FEASIBILITY]


def feasibility_cap(paths, step_codes):
    """Prompt rule: a path is as hard as its hardest step; the threat may not be easier than its easiest path.
    Returns the lowest allowed code per attribute, or None if no path has a known step."""
    caps = []
    for p in paths:
        codes = [step_codes[s] for s in p if s in step_codes]
        if codes:
            caps.append([max((c[i] for c in codes if c[i] is not None), default=None) for i in range(5)])
    if not caps:
        return None
    return [min((c[i] for c in caps if c[i] is not None), default=None) for i in range(5)]


def parse_json(raw):
    """Return (data, raw_valid). Falls back to the outermost {...}, e.g. inside a markdown fence."""
    try:
        return json.loads(raw), True
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.S)
        try:
            return (json.loads(m.group()) if m else None), False
        except json.JSONDecodeError:
            return None, False


# ---------- minimal JSON schema check (types, enum, required, additionalProperties) ----------

def schema_errors(value, schema, path="$"):
    errs = []
    typ = schema.get("type")
    pytypes = {"object": dict, "array": list, "string": str}
    if typ in pytypes and not isinstance(value, pytypes[typ]):
        return [f"{path}: expected {typ}"]
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: '{value}' not in enum")
    if typ == "object":
        props = schema.get("properties", {})
        errs += [f"{path}: missing '{r}'" for r in schema.get("required", []) if r not in value]
        if schema.get("additionalProperties") is False:
            errs += [f"{path}: extra '{k}'" for k in value if k not in props]
        for k, v in value.items():
            if k in props:
                errs += schema_errors(v, props[k], f"{path}.{k}")
    if typ == "array":
        for i, v in enumerate(value):
            errs += schema_errors(v, schema.get("items", {}), f"{path}[{i}]")
    return errs


# ---------- scoring ----------

def as_ids(value):
    """Collect ID strings from a list/dict/str field, whatever shape a model used."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set().union(set(), *[as_ids(v) for v in value.values()])
    if isinstance(value, list):
        return set().union(set(), *[as_ids(v) for v in value if isinstance(v, (str, list, dict))])
    return set()


def output_ids(t):
    paths = t.get("attackPaths") if isinstance(t.get("attackPaths"), list) else []
    ids = {"damages": as_ids(t.get("damages")), "sites": as_ids(t.get("sites")),
           "interfaces": as_ids(t.get("interfaces")), "assets": as_ids(t.get("assets")),
           "steps": set().union(set(), *[as_ids(p.get("stepIds")) for p in paths if isinstance(p, dict)])}
    return ids


def find_threats(data):
    """Return the threat list: top-level 'threats', else the first nested 'threats' list."""
    if isinstance(data, dict):
        if isinstance(data.get("threats"), list):
            return data["threats"]
        for v in data.values():
            found = find_threats(v)
            if found is not None:
                return found
    return None


def score_run(raw, prompt):
    ids_by_type, example_ids, schema, inp, vocab, step_codes = prompt
    all_ids = set().union(*ids_by_type.values())
    expected = {"damages": ids_by_type.get("damages", set()), "sites": ids_by_type.get("sites", set()),
                "interfaces": ids_by_type.get("interfaces", set()), "steps": ids_by_type.get("attack_steps", set()),
                "assets": set().union(*[v for k, v in ids_by_type.items() if k in ASSET_TYPES])}
    data, raw_valid = parse_json(raw)
    r = {"raw_json_valid": raw_valid, "lenient_json_valid": data is not None}
    if data is None:
        r["format"] = "invalid"
        return r, None
    errs = schema_errors(data, schema)
    r["schema_errors"] = errs
    r["schema_valid"] = not errs
    # one combined format result: readable as returned + matches the schema
    r["format"] = "invalid" if errs else "valid" if raw_valid else "valid after cleanup"
    threat_list = find_threats(data)
    r["threats_at_top_level"] = isinstance(data, dict) and isinstance(data.get("threats"), list)
    r["other_top_level_keys"] = [k for k in data if k not in ("threats", "summary")] if isinstance(data, dict) else []
    out = {(t.get("_entityId") or t.get("entityId")): t for t in threat_list or [] if isinstance(t, dict)}
    by_id = {t["_entityId"]: t for t in inp}
    editable = [t for t in inp if t["status"] == "inProgress"]
    copies = [t for t in editable if t["name"].startswith("COPY")]
    originals = [t for t in editable if t not in copies]

    # Layer 2: coverage
    r["threats_returned"] = len(out)
    r["editable_returned"] = sum(t["_entityId"] in out for t in editable)
    r["originals_returned"] = f"{sum(t['_entityId'] in out for t in originals)}/{len(originals)}"
    r["copies_returned"] = f"{sum(t['_entityId'] in out for t in copies)}/{len(copies)}"
    fin_changed = []
    for t in inp:
        if t["status"] == "finalized" and t["_entityId"] in out:
            o = out[t["_entityId"]]
            if any(norm(o.get(f)) != norm(t[f]) for f in ["name", "description", "rationale"] + FEASIBILITY):
                fin_changed.append(t["name"])
    r["finalized_returned"] = sum(t["status"] == "finalized" and t["_entityId"] in out for t in inp)
    r["finalized_changed"] = fin_changed
    r["new_threat_ids"] = [k for k in out if k not in by_id]
    r["junk_left_in_names"] = [t.get("name") for t in out.values() if re.search(r"HELLO|sdrg|COPY", t.get("name") or "")]

    # Layer 3: grounding
    total = invented = wrong_type = leaked = 0
    problems = []
    for tid, t in out.items():
        for kind, ids in output_ids(t).items():
            for i in ids:
                total += 1
                if i not in all_ids:
                    invented += 1
                    leaked += i in example_ids
                    problems.append(f"{t.get('name')}: {kind} {i} {'from examples' if i in example_ids else 'does not exist'}")
                elif i not in expected[kind]:
                    wrong_type += 1
                    problems.append(f"{t.get('name')}: {kind} {i} is another element type")
    r.update(linked_ids=total, invented_ids=invented, example_ids_leaked=leaked, wrong_type_ids=wrong_type,
             grounding_problems=problems)

    # Layer 2 again: "addressed" per threat
    addressed = []
    for t in editable:
        o = out.get(t["_entityId"])
        if not o:
            continue
        ids = output_ids(o)
        ok = (all(ids[k] for k in ("damages", "sites", "interfaces", "assets"))
              and all(o.get(f) for f in FEASIBILITY) and o.get("rationale")
              and all(i in expected[k] for k, v in ids.items() for i in v))
        addressed.append(bool(ok))
    r["addressed"] = f"{sum(addressed)} of {len(editable)} editable ({len(originals)} real + {len(copies)} copies)"

    # Layer 4: rules
    texts = [(t.get("name"), f, t.get(f) or "") for t in out.values() for f in ("name", "description", "rationale")]
    texts.append(("summary", "summary", data.get("summary") or ""))
    r["ids_in_text"] = [f"{n}.{f}" for n, f, s in texts if HEX_ID.search(s)]
    r["enum_names_in_text"] = [f"{n}.{f}" for n, f, s in texts if ENUM_WORDS.search(s)]
    r["anonymized_in_text"] = [f"{n}.{f}" for n, f, s in texts if "anonymi" in s.lower()]
    r["non_ascii_letters"] = sorted({c for _, _, s in texts for c in s if ord(c) > 0x24F})
    r["abbreviations"] = sorted({a for _, _, s in texts for a in ABBREV.findall(s)})
    r["max_name_words"] = max((len((t.get("name") or "").split()) for t in out.values()), default=0)
    n = max(len(out), 1)
    r["avg_description_chars"] = round(sum(len(t.get("description") or "") for t in out.values()) / n)
    r["avg_rationale_chars"] = round(sum(len(t.get("rationale") or "") for t in out.values()) / n)
    r["attack_paths"] = sum(len(t.get("attackPaths") or []) for t in out.values())

    # Attack paths versus input, and the feasibility rule. attackPaths is not required by the schema,
    # so a threat without paths counts as "paths unchanged" and is checked against the input's paths.
    path_status = {"kept": 0, "changed": 0, "omitted (input paths used)": 0, "none": 0}
    violations = []
    for tid, o in out.items():
        t = by_id.get(tid)
        old = t["paths"] if t else []
        new = [as_ids(p.get("stepIds")) for p in o.get("attackPaths") or [] if isinstance(p, dict)]
        if new:
            same = {frozenset(p) for p in new} == {frozenset(p) for p in old}
            path_status["kept" if same else "changed"] += 1
        elif old:
            path_status["omitted (input paths used)"] += 1
        else:
            path_status["none"] += 1
        cap = feasibility_cap(new or old, step_codes)
        if cap is None:
            continue
        mine = rating_codes(o)
        for i, f in enumerate(FEASIBILITY):
            if mine[i] is not None and cap[i] is not None and mine[i] < cap[i]:
                violations.append(f"{o.get('name')}: {f} '{o.get(f)}' is easier than its attack paths allow "
                                  f"('{SCALES[f][cap[i]]}' or harder){'' if new else ' (input paths)'}")
    r["attack_paths_vs_input"] = path_status
    r["feasibility_rule_violations"] = violations
    # hallucination proxy: words in the output's free text that appear nowhere in the prompt
    words = {w for _, _, s in texts for w in re.findall(r"[a-z]+", s.lower()) if len(w) > 3}
    r["words_not_in_prompt"] = sorted(words - vocab)
    summ = data.get("summary") or ""
    r["summary_present"] = bool(summ)
    r["summary_has_count"] = bool(re.search(r"\d|\b(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen)\b", summ, re.I))
    r["summary_has_significance"] = bool(re.search(r"\b(low|medium|moderate|high)\b.{0,20}significan|significan.{0,30}\b(low|medium|moderate|high)\b", summ, re.I))

    # Changes versus input
    changes = []
    for tid, o in out.items():
        t = by_id.get(tid)
        if not t:
            changes.append({"threat": o.get("name"), "new": True})
            continue
        ids = output_ids(o)
        old_assets = set().union(*t["assets"].values())
        changes.append({
            "input_name": t["name"], "output_name": o.get("name"),
            "ratings_changed": {f: f"{t[f]} -> {o.get(f)}" for f in FEASIBILITY if o.get(f) != t[f]},
            "damages +/-": (len(ids["damages"] - t["damages"]), len(t["damages"] - ids["damages"])),
            "assets +/-": (len(ids["assets"] - old_assets), len(old_assets - ids["assets"])),
            "sites +/-": (len(ids["sites"] - t["sites"]), len(t["sites"] - ids["sites"])),
            "interfaces +/-": (len(ids["interfaces"] - t["interfaces"]), len(t["interfaces"] - ids["interfaces"])),
            "steps +/-": (len(ids["steps"] - t["steps"]), len(t["steps"] - ids["steps"])),
        })
    r["changes_vs_input"] = changes
    return r, out


def stability(outputs):
    pairs = list(combinations(outputs, 2))
    same = tot = 0
    jac = []
    for a, b in pairs:
        for tid in set(a) & set(b):
            for f in FEASIBILITY:
                tot += 1
                same += a[tid].get(f) == b[tid].get(f)
            ia, ib = output_ids(a[tid]), output_ids(b[tid])
            for k in ia:
                u = ia[k] | ib[k]
                if u:
                    jac.append(len(ia[k] & ib[k]) / len(u))
    return {"rating_agreement": round(same / tot, 3) if tot else None,
            "mean_link_jaccard": round(sum(jac) / len(jac), 3) if jac else None,
            "threat_sets_identical": len({frozenset(o) for o in outputs}) == 1}


# ==================================================
# SCORER (the 7 agreed scores, from scorer.py)
# ==================================================

# Threats whose input ratings were set wrong on purpose, with the value they should get.
# Only counted if the threat ID is actually in the prompt; otherwise seeded_fixed shows "n/a".
SEEDED = {"69df43ce7749829f05ac076b": ("LIN window spoof", "43331", "22131"),
          "69f10aaa1111aaaa1111aaaa": ("Wiper spoof", "43331", "12121")}


def code_str(t):
    return "".join("?" if c is None else str(c) for c in rating_codes(t))


def seeded_fixed(t, seeded, reference):
    got = rating_codes(t)
    if None in got or code_str(t) == seeded:
        return False
    return all(abs(g - int(r)) <= 1 for g, r in zip(got, reference))


def score_answer(text, prompt):
    """Score one answer (the raw text the model returned). Returns a flat dict."""
    ids_by_type, _, schema, inp, _, _ = prompt
    all_ids = set().union(*ids_by_type.values())
    real = [t for t in inp if t["status"] == "inProgress" and not t["name"].startswith("COPY")]
    input_ids = {t["_entityId"] for t in inp}
    seeded_here = {k: v for k, v in SEEDED.items() if k in input_ids}   # only traps that exist in this prompt

    row = {"completed": False, "completion_note": "", "format": "invalid", "schema_errors": None,
           "threats_found": 0, "threats_total": len(real), "threats_missing": [t["name"] for t in real],
           "invented_ids": None, "invented_id_list": [], "seeded_fixed": 0, "seeded_total": len(seeded_here),
           "seeded_ratings": {}, "_threats": None}
    if not (text or "").strip():
        row["completion_note"] = "empty answer"
        return row
    data, raw_valid = parse_json(text)
    if data is None:
        row["completion_note"] = "no readable JSON (refused, cut off or broken)"
        return row
    row["completed"] = True

    # 1. format
    errs = schema_errors(data, schema)
    row["schema_errors"] = len(errs)
    row["format"] = "invalid" if errs else "valid" if raw_valid else "valid after cleanup"

    out = {(t.get("_entityId") or t.get("entityId")): t for t in find_threats(data) or [] if isinstance(t, dict)}
    row["_threats"] = out

    # 2. threats found
    row["threats_found"] = sum(t["_entityId"] in out for t in real)
    row["threats_missing"] = [t["name"] for t in real if t["_entityId"] not in out]

    # 3. invented IDs
    invented = sorted({i for t in out.values() for ids in output_ids(t).values() for i in ids if i not in all_ids})
    row["invented_ids"] = len(invented)
    row["invented_id_list"] = invented

    # 4. seeded errors
    for tid, (name, seeded, reference) in seeded_here.items():
        t = out.get(tid)
        row["seeded_ratings"][name] = code_str(t) if t else "not returned"
        row["seeded_fixed"] += bool(t) and seeded_fixed(t, seeded, reference)
    return row


def mean(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else None


def summarize(rows):
    """One dict per model: the 7 scores over its runs."""
    models = {}
    for r in rows:
        models.setdefault(r["model"], []).append(r)
    result = []
    for model, runs in models.items():
        done = [r for r in runs if r["completed"]]
        outs = [r["_threats"] for r in done if r["_threats"]]
        seeded_total = sum(r["seeded_total"] for r in runs)
        result.append({
            "model": model,
            "runs": len(runs),
            "completed": f"{len(done)}/{len(runs)}",
            "format_valid": f"{sum(r['format'] == 'valid' for r in runs)}/{len(runs)}",
            "format_valid_after_cleanup": sum(r["format"] == "valid after cleanup" for r in runs),
            "threats_found_mean": mean([r["threats_found"] for r in done]),
            "threats_total": runs[0]["threats_total"],
            "runs_without_invented_ids": f"{sum(r['invented_ids'] == 0 for r in done)}/{len(runs)}",
            "invented_ids_total": sum(r["invented_ids"] or 0 for r in done),
            "seeded_fixed": f"{sum(r['seeded_fixed'] for r in runs)}/{seeded_total}" if seeded_total else "n/a",
            "repeatability": stability(outs)["rating_agreement"] if len(outs) >= 2 else None,
            "seconds_mean": mean([r["seconds"] for r in runs]),
            "input_tokens_mean": mean([r["input_tokens"] for r in runs]),
            "output_tokens_mean": mean([r["output_tokens"] for r in runs]),
        })
    return result


# ==================================================
# HOSTS (call + extract per host)
# ==================================================
class ResponseResults:

    # ---------- OpenRouter ----------
    def open_router_call(payload, key):
        return requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json=payload,
            timeout=120,
        )

    def open_router(response):
        response.raise_for_status()   # HTTP errors (401, 429, 500...) become exceptions here
        data = response.json()

        usage = data.get("usage") or {}
        details = usage.get("completion_tokens_details") or {}
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}

        return {
            "model": data.get("model"),
            "provider": data.get("provider"),
            "text": message.get("content"),
            "input_tokens": usage.get("prompt_tokens"),
            "output_tokens": usage.get("completion_tokens"),
            "reasoning_tokens": details.get("reasoning_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "cost": usage.get("cost"),
            "finish_reason": choice.get("finish_reason"),
        }

    # ---------- Mapping ----------
    ResponseMapping = {
        "openrouter": {
            "call": open_router_call,
            "extract": open_router,
        },
    }


# ==================================================
# CONFIG (paths relative to app.py, folders created automatically)
# ==================================================
BASE_DIR = Path(__file__).parent
SAVE_DIR = BASE_DIR / "outputs"        # answer .json files
RUNS_CSV = BASE_DIR / "runs.csv"       # run log (one row per run)
SCORE_DIR = BASE_DIR / "scores"        # score CSVs
SAVE_DIR.mkdir(parents=True, exist_ok=True)
SCORE_DIR.mkdir(parents=True, exist_ok=True)

COLUMNS = [
    "file", "model", "run", "prompt", "date", "provider", "temperature", "top_p",
    "max_tokens", "reasoning", "input_tokens", "output_tokens", "reasoning_tokens",
    "total_tokens", "cost", "seconds", "finish_reason", "error", "run_by",
    "interface", "prompt_delivery",
]


# ==================================================
# RUN HELPERS
# ==================================================
def body(model, prompt_text, temperature, top_p=None, max_tokens=None, reasoning=None):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt_text}],
        "temperature": temperature,
        "provider": {
            # "data_collection": "deny",
            "allow_fallbacks": False,
            "require_parameters": True,
        },
    }
    if top_p is not None:
        payload["top_p"] = top_p
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    if reasoning is not None:
        payload["reasoning"] = {"enabled": reasoning}
    return payload


def run_once(payload, host, api_key):
    result = {"model": payload["model"],
              "temperature": payload.get("temperature"),
              "top_p": payload.get("top_p"),
              "max_tokens": payload.get("max_tokens"),
              "reasoning": payload.get("reasoning", {}).get("enabled"),
              "text": "", "finish_reason": "", "input_tokens": None, "output_tokens": None,
              "reasoning_tokens": None, "cost": None, "provider": "",
              "seconds": None, "error": ""}
    response = None
    start = time.perf_counter()

    try:
        response = ResponseResults.ResponseMapping[host]["call"](payload, api_key)
        data = ResponseResults.ResponseMapping[host]["extract"](response)

        for key in ["text", "finish_reason", "input_tokens", "output_tokens",
                    "reasoning_tokens", "cost", "provider"]:
            result[key] = data[key]
        result["text"] = result["text"] or ""
    except Exception as e:
        result["error"] = str(e)
        if response is not None:
            result["error"] += " | " + getattr(response, "text", "")

    result["seconds"] = round(time.perf_counter() - start, 2)
    return result


def save_run(result, label, prompt_name, host, out_dir=SAVE_DIR, runs_csv=RUNS_CSV):
    out_dir, runs_csv = Path(out_dir), Path(runs_csv)

    # 1. the answer file (only if the run succeeded)
    model = result["model"]
    stem = f"{model}-{label}".replace("/", "-").replace(":", "-").replace("_", "-")
    numbers = []
    for f in out_dir.glob(f"{stem}_run_*.json"):
        number_text = f.stem.rsplit("_run_", 1)[1]
        if number_text.isdigit():
            numbers.append(int(number_text))
    n = max(numbers, default=0) + 1

    path = None
    if not result["error"]:
        path = out_dir / f"{stem}_run_{n}.json"
        path.write_text(result["text"], encoding="utf-8")

    # 2. the CSV row
    tin, tout = result["input_tokens"], result["output_tokens"]
    row = {
        "file": path.name if path else "",
        "model": model,
        "run": n,
        "prompt": prompt_name,
        "date": datetime.now().isoformat(),
        "provider": result["provider"],
        "temperature": result["temperature"],
        "top_p": result["top_p"],
        "max_tokens": result["max_tokens"],
        "reasoning": result["reasoning"],
        "input_tokens": tin,
        "output_tokens": tout,
        "reasoning_tokens": result["reasoning_tokens"],
        "total_tokens": tin + tout if tin is not None and tout is not None else None,
        "cost": result["cost"],
        "seconds": result["seconds"],
        "finish_reason": result["finish_reason"],
        "error": result["error"],
        "run_by": "Nexademy_team",
        "interface": host,
        "prompt_delivery": "streamlit",
    }
    header = not runs_csv.exists() or runs_csv.stat().st_size == 0
    pd.DataFrame([row], columns=COLUMNS).to_csv(runs_csv, mode="a", header=header, index=False)

    return path, row


# ==================================================
# SCORING HELPERS
# ==================================================
def score_batch(batch):
    """Score every run of the batch against the prompt it was run with.
    Returns (run_rows, model_rows, problems). Never raises: problems are collected instead."""
    prompts, rows, problems = {}, [], []

    for item in batch:
        key = item["label"]
        if key not in prompts:
            try:
                prompts[key] = load_prompt_text(item["prompt_text"])
            except Exception as e:
                prompts[key] = None
                problems.append(f"Prompt '{key}' is not in the benchmark XML format, its runs were not scored ({e})")
        prompt = prompts[key]
        if prompt is None:
            continue

        r = item["row"]
        try:
            score = score_answer(item["text"], prompt)   # failed runs have text "" -> completed = False
        except Exception as e:
            problems.append(f"Could not score {r['model']} run {r['run']}: {e}")
            continue

        rows.append({
            "file": r["file"],
            "model": f"{r['model']} [{item['label']}]",   # model + prompt, so different prompts aren't mixed
            "run": r["run"],
            **score,
            "seconds": r["seconds"],
            "input_tokens": r["input_tokens"],
            "output_tokens": r["output_tokens"],
            "cost": r["cost"],
            "run_error": r["error"],
        })

    groups = []
    if rows:
        try:
            groups = summarize(rows)
        except Exception as e:
            problems.append(f"Could not build the per-model summary: {e}")
    return rows, groups, problems


def to_table(rows):
    """DataFrame for display/CSV: drop the big _threats dict, turn lists/dicts into text."""
    df = pd.DataFrame(rows).drop(columns="_threats", errors="ignore")
    for c in df.columns:
        df[c] = df[c].map(lambda v: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v)
    return df


def clean_name(name):
    name = name.strip()
    if name.lower().endswith(".csv"):
        name = name[:-4]
    for suffix in ("_runs", "_models"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return re.sub(r'[\\/:*?"<>|]', "-", name)


def save_scores(runs_df, models_df, name, create_new):
    """create_new=True: make <name>_runs.csv + <name>_models.csv (refuses to overwrite).
    create_new=False: add the rows to the existing files (columns matched by name)."""
    name = clean_name(name)
    if not name:
        raise ValueError("Enter a file name")
    targets = [(runs_df, SCORE_DIR / f"{name}_runs.csv"), (models_df, SCORE_DIR / f"{name}_models.csv")]

    if create_new:
        taken = [p.name for _, p in targets if p.exists()]
        if taken:
            raise FileExistsError(f"{', '.join(taken)} already exists. Pick another name or add to it instead")

    written = []
    for df, path in targets:
        if not create_new and path.exists() and path.stat().st_size > 0:
            old = pd.read_csv(path)
            df = pd.concat([old, df], ignore_index=True)   # matches columns by name, new columns are added
        df.to_csv(path, index=False, encoding="utf-8")
        written.append(path.name)
    return written


# ==================================================
# PAGE
# ==================================================
st.title("KPI Model Runner")

# ------- HOST -------
host = st.selectbox("Choose a host", list(ResponseResults.ResponseMapping))

# ------- API KEY -------
api_key = st.text_input("API key", type="password")
if not api_key:
    st.info("Paste your API key to continue")
    st.stop()

# ------- PROMPT SOURCE (outside the form so it switches instantly) -------
prompt_source = st.radio("Prompt source", ["Type it", "Upload files"], horizontal=True)

# ------- SETTINGS -------
with st.form("settings"):
    models_text = st.text_area("Models (one per line)", placeholder="mistralai/mistral-large")

    if prompt_source == "Type it":
        prompt_text = st.text_area("Prompt")
        prompt_label = st.text_input("Prompt label (used in file names)", value="prompt")
        uploaded = None
    else:
        uploaded = st.file_uploader("Prompt files", type=["xml", "txt", "md"], accept_multiple_files=True)

    temperature = st.slider("Temperature", 0.0, 2.0, 0.7, step=0.1)

    use_top_p = st.checkbox("Set top_p")
    top_p_value = st.slider("top_p", 0.0, 1.0, 1.0, step=0.05)

    use_max = st.checkbox("Set max_tokens")
    max_value = st.number_input("max_tokens", min_value=1, value=1000, step=100)

    reasoning_choice = st.selectbox("Reasoning", ["Don't send", "On", "Off"])

    n_runs = st.number_input("Runs per model and prompt", min_value=1, max_value=20, value=1)

    submitted = st.form_submit_button("Run")

# ------- RUN -------
if submitted:
    top_p = top_p_value if use_top_p else None
    max_tokens = int(max_value) if use_max else None
    reasoning = {"Don't send": None, "On": True, "Off": False}[reasoning_choice]
    models = [m.strip() for m in models_text.splitlines() if m.strip()]

    # (label, prompt_name, text)
    prompts = []
    if prompt_source == "Type it":
        if prompt_text.strip():
            prompts.append((prompt_label, "typed", prompt_text))
    else:
        for f in uploaded or []:
            prompts.append((Path(f.name).stem, f.name, f.getvalue().decode("utf-8")))

    if not models or not prompts:
        st.warning("Enter at least one model and one prompt")
        st.stop()

    total = len(models) * len(prompts) * n_runs
    progress = st.progress(0, text="Starting...")
    batch = []
    done = 0

    for model in models:
        for label, prompt_name, text in prompts:
            for i in range(n_runs):
                payload = body(model, text, temperature, top_p, max_tokens, reasoning)
                result = run_once(payload, host, api_key)
                try:
                    path, row = save_run(result, label, prompt_name, host)
                except Exception as e:   # saving the answer must not lose the answer
                    path, row = None, {"file": "", "model": model, "run": i + 1, "prompt": prompt_name,
                                       **{k: result.get(k) for k in COLUMNS if k in result},
                                       "error": result["error"] or f"could not save: {e}"}
                batch.append({"row": row, "text": result["text"], "label": label,
                              "prompt_name": prompt_name, "prompt_text": text,
                              "path": str(path) if path else None})

                done += 1
                progress.progress(done / total, text=f"{done}/{total}: {model} | {label} | run {i + 1}")

                if done < total:
                    time.sleep(2)  # avoid rate limits

    progress.progress(1.0, text="Done")
    st.session_state["batch"] = batch

    # score right away; problems are collected, never raised
    st.session_state["scores"] = score_batch(batch)


# ------- RESULTS (from session_state, so they survive reruns) -------
if "batch" in st.session_state:
    batch = st.session_state["batch"]
    st.header("Results")

    for item in batch:
        row = item["row"]
        if row.get("error"):
            st.error(f"FAILED: {row['model']} | {item['label']} | {str(row['error'])[:200]}")
            continue
        file_name = Path(item["path"]).name if item["path"] else f"{row['model']}-{item['label']}.json"
        with st.expander(f"{file_name}  ({row.get('finish_reason')}, {row.get('seconds')}s)"):
            st.write(item["text"])
            st.download_button("Download .json", item["text"], file_name,
                               "application/json", key=f"dl_{file_name}")

    ok = [item for item in batch if item["path"]]
    if ok:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            for item in ok:
                z.write(item["path"], arcname=Path(item["path"]).name)
        st.download_button("Download all .json files (zip)", buffer.getvalue(),
                           "batch_outputs.zip", "application/zip")

    df = pd.DataFrame([item["row"] for item in batch]).reindex(columns=COLUMNS)
    st.dataframe(df)
    st.download_button("Download this batch as CSV", df.to_csv(index=False), "batch.csv", "text/csv")


# ------- SCORES -------
if "scores" in st.session_state:
    run_rows, model_rows, problems = st.session_state["scores"]
    st.header("Scores")

    for p in problems:
        st.warning(p)

    if not run_rows:
        st.info("Nothing could be scored. Scoring needs a prompt in the benchmark XML format.")
    else:
        runs_df = to_table(run_rows)
        models_df = to_table(model_rows)

        # 1. show the results first
        st.subheader("Per model")
        st.dataframe(models_df)
        with st.expander("Per run"):
            st.dataframe(runs_df)

        c1, c2 = st.columns(2)
        c1.download_button("Download per-model CSV", models_df.to_csv(index=False), "scores_models.csv", "text/csv")
        c2.download_button("Download per-run CSV", runs_df.to_csv(index=False), "scores_runs.csv", "text/csv")

        # 2. then saving: new CSV or add rows to an existing one
        st.subheader("Save scores")
        save_mode = st.radio("Save to", ["Create new CSV", "Add rows to existing CSV"], horizontal=True)

        existing = sorted({p.name[: -len("_runs.csv")] for p in SCORE_DIR.glob("*_runs.csv")})
        if save_mode == "Create new CSV":
            if "save_name" not in st.session_state:
                st.session_state["save_name"] = f"scores_{datetime.now():%Y-%m-%d_%H-%M}"
            name = st.text_input("File name", key="save_name")
        elif existing:
            name = st.selectbox("Existing file", existing)
        else:
            st.info("No score files yet. Create a new one first.")
            name = None

        if st.button("Save", disabled=not name):
            # a crash here must not touch the results above
            try:
                written = save_scores(runs_df, models_df, name, create_new=(save_mode == "Create new CSV"))
                st.success(f"Saved to scores/: {', '.join(written)}")
            except Exception as e:
                st.error(f"Saving failed: {e}. Your results above are still here and can be downloaded.")