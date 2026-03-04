#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
StateForge (single-file edition)
HAR-based workflow/state analyzer for authorized security testing.

Features:
- Parse HAR
- Infer actors from Authorization/Cookie/X-API-Key
- Infer objects from URL/body/response
- Infer actions from method/path
- Infer state transitions from request/response JSON
- Detect:
  * actor swap on owned object
  * post-terminal mutation
  * action-before-precondition
  * repeat terminal action
  * cross-tenant / owner mismatch hints
- Export text + JSON report

Usage:
    python3 stateforge.py traffic.har
    python3 stateforge.py traffic.har --json-out report.json --text-out report.txt --verbose
"""

from __future__ import annotations

import argparse
import base64
import collections
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
import textwrap
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Set

VERSION = "2026.1-singlefile"

# -----------------------------
# Configuration / heuristics
# -----------------------------

ACTION_KEYWORDS = {
    "create": {"create", "new", "register", "signup", "invite", "add"},
    "read": {"get", "view", "fetch", "list", "search", "query", "download"},
    "update": {"update", "edit", "patch", "modify", "rename", "change", "set"},
    "delete": {"delete", "remove", "destroy", "purge"},
    "submit": {"submit", "send", "push"},
    "approve": {"approve", "accept", "confirm", "verify", "validate"},
    "reject": {"reject", "decline", "deny"},
    "publish": {"publish", "release", "go-live"},
    "archive": {"archive", "close", "disable", "freeze", "lock"},
    "restore": {"restore", "reopen", "unarchive", "unlock"},
    "share": {"share", "grant", "invite", "assign"},
    "revoke": {"revoke", "unshare", "remove-member", "removeuser", "deauthorize"},
    "login": {"login", "signin", "authenticate", "token"},
    "logout": {"logout", "signout"},
    "pay": {"pay", "charge", "capture", "checkout"},
    "refund": {"refund", "reverse"},
}

TERMINAL_STATES = {
    "deleted", "archived", "closed", "disabled", "revoked", "rejected",
    "paid", "refunded", "cancelled", "canceled", "expired", "locked"
}

PRECONDITION_MAP = {
    "approve": {"submitted", "pending", "requested", "review"},
    "publish": {"approved", "ready", "draft"},
    "refund": {"paid", "captured", "completed"},
    "archive": {"approved", "published", "closed", "resolved"},
    "restore": {"archived", "deleted", "closed", "disabled"},
    "submit": {"draft", "new", "created"},
    "revoke": {"shared", "granted", "invited", "active"},
}

MUTATING_ACTIONS = {
    "create", "update", "delete", "submit", "approve", "reject",
    "publish", "archive", "restore", "share", "revoke", "pay", "refund"
}

READONLY_METHODS = {"GET", "HEAD", "OPTIONS"}

STATE_FIELD_NAMES = {
    "state", "status", "phase", "stage", "lifecycle", "approval_status",
    "payment_status", "order_status", "ticket_status", "workflow_state"
}

OWNER_FIELD_NAMES = {
    "owner", "owner_id", "ownerid", "created_by", "createdby", "user_id",
    "userid", "account_id", "accountid", "tenant_id", "tenantid",
    "workspace_id", "workspaceid", "org_id", "orgid", "team_id", "teamid"
}

ACTOR_HEADER_KEYS = {
    "authorization", "cookie", "x-api-key", "api-key", "x-auth-token",
    "x-access-token", "x-session-id", "x-user-id"
}

INTERESTING_ID_KEYS = {
    "id", "_id", "uuid", "guid", "user_id", "account_id", "tenant_id",
    "workspace_id", "org_id", "team_id", "project_id", "invoice_id",
    "order_id", "ticket_id", "draft_id", "payment_id", "document_id"
}

ID_VALUE_RE = re.compile(
    r"(?i)\b([0-9]{2,}|[0-9a-f]{8}-[0-9a-f-]{8,}|[A-Za-z0-9_-]{10,})\b"
)
PATH_ID_RE = re.compile(
    r"/([A-Za-z][A-Za-z0-9_-]{1,})/([0-9]{2,}|[0-9a-f]{8}-[0-9a-f-]{8,}|[A-Za-z0-9_-]{8,})(?=/|$)"
)
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,}")
SENSITIVE_QUERY_KEYS = {"token", "code", "key", "auth", "session", "password", "secret"}


# -----------------------------
# Data models
# -----------------------------

@dataclasses.dataclass
class RequestRecord:
    index: int
    started: str
    method: str
    url: str
    path: str
    host: str
    query: Dict[str, Any]
    req_headers: Dict[str, str]
    req_body: Any
    req_body_raw: str
    status: int
    resp_headers: Dict[str, str]
    resp_body: Any
    resp_body_raw: str
    mime_type: str
    actor_id: str
    actor_fingerprint: str
    action: str
    object_type: Optional[str]
    object_id: Optional[str]
    owner_hint: Optional[str]
    tenant_hint: Optional[str]
    pre_state: Optional[str]
    post_state: Optional[str]


@dataclasses.dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    confidence: float
    evidence: List[Dict[str, Any]]


@dataclasses.dataclass
class ObjectHistory:
    object_key: str
    object_type: str
    object_id: str
    events: List[RequestRecord]


# -----------------------------
# Utility helpers
# -----------------------------

def sha256s(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()


def short_hash(s: str, n: int = 12) -> str:
    return sha256s(s)[:n]


def safe_json_loads(text: str) -> Any:
    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        # Try base64 content from HAR if present elsewhere; otherwise fallback
        return None


def maybe_b64decode(text: str) -> Optional[str]:
    try:
        raw = base64.b64decode(text, validate=True)
        return raw.decode("utf-8", "ignore")
    except Exception:
        return None


def flatten_json(obj: Any, prefix: str = "") -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            np = f"{prefix}.{k}" if prefix else str(k)
            out.extend(flatten_json(v, np))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):  # cap traversal
            np = f"{prefix}[{i}]"
            out.extend(flatten_json(v, np))
    else:
        out.append((prefix, obj))
    return out


def get_nested_state(obj: Any) -> Optional[str]:
    if not isinstance(obj, (dict, list)):
        return None
    for k, v in flatten_json(obj):
        keyname = k.split(".")[-1].lower().replace("[0]", "")
        if keyname in STATE_FIELD_NAMES and isinstance(v, (str, int)):
            return str(v).strip().lower()
    return None


def get_owner_hint(obj: Any) -> Optional[str]:
    if not isinstance(obj, (dict, list)):
        return None
    for k, v in flatten_json(obj):
        leaf = re.sub(r"\[\d+\]", "", k.split(".")[-1].lower())
        if leaf in OWNER_FIELD_NAMES and isinstance(v, (str, int)):
            return str(v)
    return None


def first_matching_id(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        for k, v in flatten_json(obj):
            leaf = re.sub(r"\[\d+\]", "", k.split(".")[-1].lower())
            if leaf in INTERESTING_ID_KEYS and isinstance(v, (str, int)):
                return str(v)
    return None


def sanitize_url(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        cleaned = []
        for k, v in query:
            if k.lower() in SENSITIVE_QUERY_KEYS:
                cleaned.append((k, "***"))
            else:
                cleaned.append((k, v if len(v) < 80 else v[:77] + "..."))
        qs = urllib.parse.urlencode(cleaned)
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, qs, p.fragment))
    except Exception:
        return url


def header_dict(headers: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in headers or []:
        name = str(h.get("name", "")).strip()
        val = str(h.get("value", ""))
        if name:
            out[name.lower()] = val
    return out


def parse_query_string(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = {}
    for item in items or []:
        k = str(item.get("name", ""))
        v = item.get("value")
        if k:
            out[k] = v
    return out


def try_parse_post_data(post_data: Dict[str, Any]) -> Tuple[Any, str]:
    if not post_data:
        return None, ""
    text = post_data.get("text") or ""
    mime = (post_data.get("mimeType") or "").lower()

    if isinstance(text, str):
        parsed = safe_json_loads(text)
        if parsed is not None:
            return parsed, text

        decoded = maybe_b64decode(text)
        if decoded:
            parsed = safe_json_loads(decoded)
            if parsed is not None:
                return parsed, decoded

        if "application/x-www-form-urlencoded" in mime:
            try:
                q = urllib.parse.parse_qs(text, keep_blank_values=True)
                return {k: v[0] if len(v) == 1 else v for k, v in q.items()}, text
            except Exception:
                pass

    params = post_data.get("params")
    if params:
        data = {}
        for p in params:
            n = p.get("name")
            v = p.get("value")
            if n:
                data[n] = v
        return data, text

    return None, text


def try_parse_content(content: Dict[str, Any]) -> Tuple[Any, str, str]:
    if not content:
        return None, "", ""
    text = content.get("text") or ""
    mime = (content.get("mimeType") or "").lower()
    encoding = content.get("encoding")

    if encoding == "base64" and text:
        decoded = maybe_b64decode(text)
        if decoded is not None:
            text = decoded

    parsed = safe_json_loads(text)
    if parsed is not None:
        return parsed, text, mime

    return None, text, mime


def infer_actor(req_headers: Dict[str, str]) -> Tuple[str, str]:
    parts = []
    for k in sorted(ACTOR_HEADER_KEYS):
        if k in req_headers and req_headers[k]:
            value = req_headers[k]
            if k == "cookie":
                # normalize cookie order and strip obvious junk
                cookies = []
                for item in value.split(";"):
                    item = item.strip()
                    if item:
                        cookies.append(item)
                value = ";".join(sorted(cookies))
            parts.append(f"{k}={value}")
    if not parts:
        return "actor:anonymous", "anonymous"
    fp = "|".join(parts)
    return f"actor:{short_hash(fp, 10)}", fp


def infer_action(method: str, path: str) -> str:
    method = method.upper()
    path_parts = [p for p in path.strip("/").split("/") if p]
    lower_parts = [p.lower() for p in path_parts]

    # method-based defaults
    if method == "POST":
        default = "create"
    elif method in {"PUT", "PATCH"}:
        default = "update"
    elif method == "DELETE":
        default = "delete"
    elif method in READONLY_METHODS:
        default = "read"
    else:
        default = "unknown"

    # path keyword override
    for action, kws in ACTION_KEYWORDS.items():
        for part in lower_parts[-3:]:
            if part in kws:
                return action
            tokenized = set(re.split(r"[-_]", part))
            if kws & tokenized:
                return action

    return default


def infer_object_type_and_id(path: str, req_body: Any, resp_body: Any) -> Tuple[Optional[str], Optional[str]]:
    # 1) URL path /resource/<id>
    m = PATH_ID_RE.search(path)
    if m:
        return m.group(1).lower(), m.group(2)

    # 2) Request body
    rid = first_matching_id(req_body)
    if rid:
        return "object", rid

    # 3) Response body
    rid = first_matching_id(resp_body)
    if rid:
        return "object", rid

    # 4) Query-ish path fallback
    parts = [p for p in path.strip("/").split("/") if p]
    parts = [p for p in parts if not ID_VALUE_RE.fullmatch(p)]
    if parts:
        last = parts[-1].lower()
        if last not in {"api", "v1", "v2", "v3"}:
            return last, None

    return None, None


def infer_tenant_hint(path: str, req_body: Any, resp_body: Any, query: Dict[str, Any]) -> Optional[str]:
    # query keys
    for k, v in query.items():
        lk = k.lower()
        if lk in {"tenant", "tenant_id", "workspace", "workspace_id", "org", "org_id", "team", "team_id"}:
            return str(v)

    # body
    for src in (req_body, resp_body):
        if isinstance(src, (dict, list)):
            for k, v in flatten_json(src):
                leaf = re.sub(r"\[\d+\]", "", k.split(".")[-1].lower())
                if leaf in {"tenant_id", "tenantid", "workspace_id", "workspaceid", "org_id", "orgid", "team_id", "teamid"}:
                    return str(v)

    # path hints
    m = re.search(r"/(tenants|workspaces|orgs|teams)/([^/]+)", path, re.I)
    if m:
        return m.group(2)

    return None


def infer_states(action: str, req_body: Any, resp_body: Any, status: int) -> Tuple[Optional[str], Optional[str]]:
    req_state = get_nested_state(req_body)
    resp_state = get_nested_state(resp_body)

    # If response gives a state, trust it as post_state.
    post_state = resp_state

    # pre_state may be in request payload (e.g. explicit expected state), else infer from action map
    pre_state = req_state

    if not pre_state and action in PRECONDITION_MAP:
        # unknown pre-state; leave None to avoid overclaiming
        pre_state = None

    # heuristic post-state by action
    if not post_state and 200 <= status < 300:
        post_guess = {
            "create": "created",
            "submit": "submitted",
            "approve": "approved",
            "reject": "rejected",
            "publish": "published",
            "archive": "archived",
            "restore": "active",
            "delete": "deleted",
            "share": "shared",
            "revoke": "revoked",
            "pay": "paid",
            "refund": "refunded",
            "update": "updated",
        }
        post_state = post_guess.get(action)

    return (
        pre_state.lower() if isinstance(pre_state, str) else pre_state,
        post_state.lower() if isinstance(post_state, str) else post_state,
    )


def compact_evidence(r: RequestRecord) -> Dict[str, Any]:
    return {
        "index": r.index,
        "started": r.started,
        "method": r.method,
        "url": sanitize_url(r.url),
        "status": r.status,
        "actor_id": r.actor_id,
        "action": r.action,
        "object_type": r.object_type,
        "object_id": r.object_id,
        "pre_state": r.pre_state,
        "post_state": r.post_state,
        "owner_hint": r.owner_hint,
        "tenant_hint": r.tenant_hint,
    }


# -----------------------------
# HAR parsing
# -----------------------------

def parse_har(path: str, verbose: bool = False) -> List[RequestRecord]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    entries = data.get("log", {}).get("entries", [])
    records: List[RequestRecord] = []

    for idx, entry in enumerate(entries):
        req = entry.get("request", {})
        resp = entry.get("response", {})

        url = req.get("url") or ""
        method = (req.get("method") or "GET").upper()
        started = entry.get("startedDateTime") or ""

        try:
            p = urllib.parse.urlsplit(url)
            path_only = p.path or "/"
            host = p.netloc
        except Exception:
            path_only = "/"
            host = ""

        req_headers = header_dict(req.get("headers", []))
        resp_headers = header_dict(resp.get("headers", []))
        query = parse_query_string(req.get("queryString", []))
        req_body, req_body_raw = try_parse_post_data(req.get("postData") or {})
        resp_body, resp_body_raw, mime_type = try_parse_content(resp.get("content") or {})

        actor_id, actor_fp = infer_actor(req_headers)
        action = infer_action(method, path_only)
        object_type, object_id = infer_object_type_and_id(path_only, req_body, resp_body)
        owner_hint = get_owner_hint(resp_body) or get_owner_hint(req_body)
        tenant_hint = infer_tenant_hint(path_only, req_body, resp_body, query)
        pre_state, post_state = infer_states(action, req_body, resp_body, int(resp.get("status", 0) or 0))

        record = RequestRecord(
            index=idx,
            started=started,
            method=method,
            url=url,
            path=path_only,
            host=host,
            query=query,
            req_headers=req_headers,
            req_body=req_body,
            req_body_raw=req_body_raw,
            status=int(resp.get("status", 0) or 0),
            resp_headers=resp_headers,
            resp_body=resp_body,
            resp_body_raw=resp_body_raw,
            mime_type=mime_type,
            actor_id=actor_id,
            actor_fingerprint=actor_fp,
            action=action,
            object_type=object_type,
            object_id=object_id,
            owner_hint=owner_hint,
            tenant_hint=tenant_hint,
            pre_state=pre_state,
            post_state=post_state,
        )
        records.append(record)

    if verbose:
        print(f"[+] Parsed {len(records)} HAR entries")

    return records


# -----------------------------
# Correlation engine
# -----------------------------

def build_object_histories(records: List[RequestRecord]) -> Dict[str, ObjectHistory]:
    histories: Dict[str, ObjectHistory] = {}

    for r in records:
        if not r.object_type or not r.object_id:
            continue
        key = f"{r.object_type}:{r.object_id}"
        if key not in histories:
            histories[key] = ObjectHistory(
                object_key=key,
                object_type=r.object_type,
                object_id=r.object_id,
                events=[],
            )
        histories[key].events.append(r)

    for h in histories.values():
        h.events.sort(key=lambda x: (x.started, x.index))
    return histories


def infer_first_creator(history: ObjectHistory) -> Optional[RequestRecord]:
    for ev in history.events:
        if ev.action == "create" and 200 <= ev.status < 300:
            return ev
    # fallback: first mutating successful request
    for ev in history.events:
        if ev.action in MUTATING_ACTIONS and 200 <= ev.status < 300:
            return ev
    return history.events[0] if history.events else None


def state_sequence(history: ObjectHistory) -> List[str]:
    seq = []
    for ev in history.events:
        if ev.post_state:
            seq.append(ev.post_state)
    return seq


# -----------------------------
# Detection logic
# -----------------------------

def detect_actor_swap(histories: Dict[str, ObjectHistory]) -> List[Finding]:
    findings: List[Finding] = []

    for key, hist in histories.items():
        creator = infer_first_creator(hist)
        if not creator:
            continue

        owner_actor = creator.actor_id

        for ev in hist.events:
            if ev.actor_id != owner_actor and ev.action in MUTATING_ACTIONS and 200 <= ev.status < 300:
                sev = "high"
                conf = 0.82
                if ev.action in {"approve", "refund", "delete", "archive", "revoke"}:
                    sev = "critical"
                    conf = 0.91

                findings.append(Finding(
                    severity=sev,
                    category="actor-swap",
                    title=f"Cross-actor mutating action on {key}",
                    description=(
                        f"Object appears to be created/owned by {owner_actor}, but a different actor "
                        f"({ev.actor_id}) successfully performed mutating action '{ev.action}'. "
                        f"This may indicate broken object authorization, stale capability, or privilege drift."
                    ),
                    confidence=conf,
                    evidence=[compact_evidence(creator), compact_evidence(ev)],
                ))
                break

    return findings


def detect_post_terminal_mutation(histories: Dict[str, ObjectHistory]) -> List[Finding]:
    findings: List[Finding] = []

    for key, hist in histories.items():
        terminal_seen = None

        for ev in hist.events:
            if ev.post_state in TERMINAL_STATES or ev.action in {"delete", "archive", "revoke", "refund"}:
                terminal_seen = ev
                continue

            if terminal_seen and ev.action in MUTATING_ACTIONS and 200 <= ev.status < 300:
                findings.append(Finding(
                    severity="high",
                    category="post-terminal-mutation",
                    title=f"Mutation after terminal state on {key}",
                    description=(
                        f"A terminal state/action was observed first ('{terminal_seen.post_state or terminal_seen.action}'), "
                        f"but later a successful mutating action '{ev.action}' was accepted. "
                        f"This may indicate invalid lifecycle enforcement."
                    ),
                    confidence=0.88,
                    evidence=[compact_evidence(terminal_seen), compact_evidence(ev)],
                ))
                break

    return findings


def detect_action_before_precondition(histories: Dict[str, ObjectHistory]) -> List[Finding]:
    findings: List[Finding] = []

    for key, hist in histories.items():
        seen_states: Set[str] = set()
        seen_actions: Set[str] = set()

        for ev in hist.events:
            required = PRECONDITION_MAP.get(ev.action)
            if required and 200 <= ev.status < 300:
                ok = bool(required & seen_states)
                if not ok:
                    # also allow if explicit pre_state matches
                    if not ev.pre_state or ev.pre_state not in required:
                        findings.append(Finding(
                            severity="medium",
                            category="action-before-precondition",
                            title=f"Action '{ev.action}' may bypass expected precondition on {key}",
                            description=(
                                f"Successful action '{ev.action}' occurred without prior observed states "
                                f"{sorted(required)} for this object. This may indicate a workflow bypass or missing state gate."
                            ),
                            confidence=0.72,
                            evidence=[compact_evidence(ev)],
                        ))
                        break

            if ev.post_state:
                seen_states.add(ev.post_state)
            seen_actions.add(ev.action)

    return findings


def detect_repeat_terminal_action(histories: Dict[str, ObjectHistory]) -> List[Finding]:
    findings: List[Finding] = []

    terminal_actions = {"approve", "reject", "refund", "delete", "archive", "revoke", "pay"}

    for key, hist in histories.items():
        first_by_action: Dict[str, RequestRecord] = {}
        for ev in hist.events:
            if ev.action in terminal_actions and 200 <= ev.status < 300:
                if ev.action not in first_by_action:
                    first_by_action[ev.action] = ev
                else:
                    findings.append(Finding(
                        severity="medium",
                        category="repeat-terminal-action",
                        title=f"Repeated terminal action '{ev.action}' on {key}",
                        description=(
                            f"The same terminal/one-way action '{ev.action}' succeeded more than once on the same object. "
                            f"This may indicate replay tolerance, missing idempotency controls, or logic flaws."
                        ),
                        confidence=0.77,
                        evidence=[compact_evidence(first_by_action[ev.action]), compact_evidence(ev)],
                    ))
                    break

    return findings


def detect_owner_tenant_mismatch(histories: Dict[str, ObjectHistory]) -> List[Finding]:
    findings: List[Finding] = []

    for key, hist in histories.items():
        owners = set()
        tenants = set()
        actor_success = set()

        for ev in hist.events:
            if 200 <= ev.status < 300:
                actor_success.add(ev.actor_id)
                if ev.owner_hint:
                    owners.add(str(ev.owner_hint))
                if ev.tenant_hint:
                    tenants.add(str(ev.tenant_hint))

        if len(owners) > 1:
            findings.append(Finding(
                severity="medium",
                category="owner-mismatch",
                title=f"Multiple owner hints observed for {key}",
                description=(
                    f"The same object exhibited multiple owner identifiers in successful flows: {sorted(owners)[:8]}. "
                    f"This may indicate ownership confusion, cross-account bleed, or inconsistent authorization metadata."
                ),
                confidence=0.68,
                evidence=[compact_evidence(e) for e in hist.events[:5]],
            ))

        if len(tenants) > 1:
            findings.append(Finding(
                severity="high",
                category="tenant-mismatch",
                title=f"Multiple tenant hints observed for {key}",
                description=(
                    f"The same object appeared across multiple tenant/workspace/org identifiers in successful flows: "
                    f"{sorted(tenants)[:8]}. This may indicate tenant isolation issues."
                ),
                confidence=0.84,
                evidence=[compact_evidence(e) for e in hist.events[:6]],
            ))

        if len(actor_success) > 2 and len(hist.events) <= 6:
            findings.append(Finding(
                severity="low",
                category="multi-actor-signal",
                title=f"Object {key} was successfully touched by many actors",
                description=(
                    f"Multiple distinct actors successfully interacted with this object in a small event window. "
                    f"This is a weak signal worth manual review for collaboration abuse versus intended sharing."
                ),
                confidence=0.40,
                evidence=[compact_evidence(e) for e in hist.events[:6]],
            ))

    return findings


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (
            f.category,
            f.title,
            tuple((ev.get("index"), ev.get("actor_id"), ev.get("action"), ev.get("object_id")) for ev in f.evidence)
        )
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# -----------------------------
# Reporting
# -----------------------------

def severity_rank(sev: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1
    }.get(sev.lower(), 0)


def summarize(records: List[RequestRecord], histories: Dict[str, ObjectHistory], findings: List[Finding]) -> Dict[str, Any]:
    by_actor = collections.Counter(r.actor_id for r in records)
    by_action = collections.Counter(r.action for r in records)
    by_status = collections.Counter(r.status for r in records)
    by_category = collections.Counter(f.category for f in findings)
    by_severity = collections.Counter(f.severity for f in findings)

    return {
        "version": VERSION,
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "stats": {
            "entries": len(records),
            "objects_tracked": len(histories),
            "actors": len(by_actor),
            "findings": len(findings),
        },
        "top_actions": by_action.most_common(15),
        "status_counts": dict(by_status),
        "finding_categories": dict(by_category),
        "finding_severity": dict(by_severity),
        "actors": [{"actor_id": k, "count": v} for k, v in by_actor.most_common()],
    }


def render_text_report(summary: Dict[str, Any], findings: List[Finding]) -> str:
    lines = []
    lines.append(f"StateForge Report - version {summary['version']}")
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append("")
    lines.append("== Summary ==")
    stats = summary["stats"]
    lines.append(f"Entries         : {stats['entries']}")
    lines.append(f"Objects tracked : {stats['objects_tracked']}")
    lines.append(f"Actors          : {stats['actors']}")
    lines.append(f"Findings        : {stats['findings']}")
    lines.append("")

    lines.append("== Finding Severity ==")
    sev = summary["finding_severity"]
    for k in ("critical", "high", "medium", "low", "info"):
        if k in sev:
            lines.append(f"- {k:<8} : {sev[k]}")
    lines.append("")

    lines.append("== Top Actions ==")
    for action, count in summary["top_actions"]:
        lines.append(f"- {action:<12} {count}")
    lines.append("")

    if not findings:
        lines.append("No strong logic anomalies detected from the supplied HAR.")
        return "\n".join(lines)

    lines.append("== Findings ==")
    findings = sorted(findings, key=lambda f: (-severity_rank(f.severity), -f.confidence, f.category, f.title))

    for i, f in enumerate(findings, 1):
        lines.append("")
        lines.append(f"[{i}] {f.severity.upper()} | {f.category} | {f.title}")
        lines.append(f"Confidence: {f.confidence:.2f}")
        wrapped = textwrap.wrap(f.description, width=100)
        for w in wrapped:
            lines.append(f"  {w}")
        lines.append("  Evidence:")
        for ev in f.evidence:
            lines.append(
                f"    - #{ev['index']} {ev['method']} {ev['url']} "
                f"(status={ev['status']}, actor={ev['actor_id']}, action={ev['action']}, "
                f"obj={ev.get('object_type')}:{ev.get('object_id')}, "
                f"state={ev.get('pre_state')}->{ev.get('post_state')})"
            )

    return "\n".join(lines)


def build_json_report(summary: Dict[str, Any], findings: List[Finding], histories: Dict[str, ObjectHistory]) -> Dict[str, Any]:
    return {
        "summary": summary,
        "findings": [
            dataclasses.asdict(f) for f in sorted(
                findings,
                key=lambda f: (-severity_rank(f.severity), -f.confidence, f.category, f.title)
            )
        ],
        "objects": [
            {
                "object_key": h.object_key,
                "object_type": h.object_type,
                "object_id": h.object_id,
                "events": [compact_evidence(ev) for ev in h.events]
            }
            for h in histories.values()
        ]
    }


# -----------------------------
# Main analysis pipeline
# -----------------------------

def analyze(records: List[RequestRecord], verbose: bool = False) -> Tuple[Dict[str, ObjectHistory], List[Finding]]:
    histories = build_object_histories(records)

    if verbose:
        print(f"[+] Built {len(histories)} object histories")

    findings: List[Finding] = []
    findings.extend(detect_actor_swap(histories))
    findings.extend(detect_post_terminal_mutation(histories))
    findings.extend(detect_action_before_precondition(histories))
    findings.extend(detect_repeat_terminal_action(histories))
    findings.extend(detect_owner_tenant_mismatch(histories))
    findings = dedupe_findings(findings)

    if verbose:
        print(f"[+] Generated {len(findings)} deduplicated findings")

    return histories, findings


# -----------------------------
# CLI
# -----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="StateForge - HAR-based workflow/state analyzer for authorized security testing"
    )
    p.add_argument("har", help="Path to HAR file")
    p.add_argument("--json-out", help="Write JSON report to this file")
    p.add_argument("--text-out", help="Write text report to this file")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="info")
    return p.parse_args()


def filter_findings(findings: List[Finding], min_sev: str) -> List[Finding]:
    threshold = severity_rank(min_sev)
    return [f for f in findings if severity_rank(f.severity) >= threshold]


def main() -> int:
    args = parse_args()

    if not os.path.isfile(args.har):
        print(f"[-] HAR file not found: {args.har}", file=sys.stderr)
        return 2

    try:
        records = parse_har(args.har, verbose=args.verbose)
    except Exception as e:
        print(f"[-] Failed to parse HAR: {e}", file=sys.stderr)
        return 2

    histories, findings = analyze(records, verbose=args.verbose)
    findings = filter_findings(findings, args.min_severity)

    summary = summarize(records, histories, findings)
    text_report = render_text_report(summary, findings)
    json_report = build_json_report(summary, findings, histories)

    print(text_report)

    if args.text_out:
        with open(args.text_out, "w", encoding="utf-8") as f:
            f.write(text_report)
        if args.verbose:
            print(f"[+] Wrote text report: {args.text_out}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)
        if args.verbose:
            print(f"[+] Wrote JSON report: {args.json_out}")

    # exit codes:
    # 0 = no findings
    # 1 = findings present
    # 2 = error
    sev_counts = collections.Counter(f.severity for f in findings)
    if sev_counts.get("critical") or sev_counts.get("high"):
        return 1
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
