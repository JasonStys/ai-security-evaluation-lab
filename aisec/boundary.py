"""Jason Stys: fail-closed in-memory tool broker, exact single-use approvals and bounded output validation."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: CANARY — line 117
# variable: VARIANTS — line 118
# variable: byte — line 122
# definition: Context — line 127
# variable: tenant — line 130
# variable: user — line 131
# variable: session — line 132
# variable: scopes — line 133
# variable: policy_revision — line 134
# definition: Action — line 138
# variable: tool — line 141
# variable: resource — line 142
# variable: revision — line 143
# variable: text — line 144
# definition: from_json — line 147
# parameter: cls — line 147
# parameter: value — line 147
# variable: tool — line 154
# variable: data — line 155
# variable: text — line 162
# definition: Approval — line 169
# variable: nonce — line 172
# variable: expires — line 173
# variable: binding — line 174
# variable: mac — line 175
# definition: Authority — line 178
# definition: __init__ — line 181
# parameter: self — line 181
# attribute: _key — line 183
# attribute: _spent — line 184
# attribute: _lock — line 185
# definition: binding — line 188
# parameter: action — line 188
# parameter: context — line 188
# definition: signature — line 192
# parameter: binding — line 192
# parameter: expires — line 192
# parameter: nonce — line 192
# parameter: self — line 192
# definition: issue — line 198
# parameter: action — line 198
# parameter: context — line 198
# parameter: now — line 198
# parameter: self — line 198
# variable: nonce — line 200
# variable: binding — line 201
# definition: consume — line 206
# parameter: action — line 207
# parameter: approval — line 207
# parameter: context — line 207
# parameter: now — line 207
# parameter: self — line 207
# definition: Decision — line 230
# variable: verdict — line 233
# variable: reason — line 234
# variable: completed — line 235
# variable: effects — line 236
# definition: contains_canary — line 239
# parameter: text — line 239
# variable: normalized — line 241
# variable: value — line 244
# definition: Broker — line 248
# definition: __init__ — line 251
# parameter: authority — line 251
# parameter: context — line 251
# parameter: self — line 251
# attribute: context — line 253
# attribute: authority — line 254
# attribute: revision — line 255
# attribute: effects — line 256
# attribute: _lock — line 257
# definition: execute — line 259
# parameter: action — line 259
# parameter: approval — line 259
# parameter: now — line 259
# parameter: self — line 259
# variable: payload — line 262
# variable: scope — line 273
# attribute: effects — line 285
# attribute: revision — line 286
# definition: handle — line 289
# parameter: approval — line 290
# parameter: now — line 290
# parameter: response — line 290
# parameter: self — line 290
# variable: data — line 294
# variable: answer — line 295
# variable: actions — line 296
# variable: citations — line 296
# variable: item — line 302
# variable: action — line 305
# variable: item — line 308
# END CODE MAP

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import unicodedata
from dataclasses import dataclass
from typing import Any

from aisec.contracts import (
    ContractError,
    bounded_text,
    canonical,
    digest,
    fields,
    identifier,
)

CANARY = "LAB-CANARY-DO-NOT-USE-42"
VARIANTS = (
    CANARY,
    base64.b64encode(CANARY.encode()).decode(),
    CANARY.encode().hex(),
    "".join(f"%{byte:02X}" for byte in CANARY.encode()),
)


@dataclass(frozen=True)
class Context:
    """Trusted caller/session capability context supplied by the harness, never by an AI message."""

    tenant: str = "tenant-a"
    user: str = "user-a"
    session: str = "session-a"
    scopes: tuple[str, ...] = ("read", "draft")
    policy_revision: int = 1


@dataclass(frozen=True)
class Action:
    """Validated narrow tool call; resource revisions prevent approval use after state changes."""

    tool: str
    resource: str
    revision: int
    text: str = ""

    @classmethod
    def from_json(cls, value: Any) -> Action:
        """Accept read_document or draft_note only; no shell, URL fetch or arbitrary SQL tools exist."""
        if not isinstance(value, dict) or value.get("tool") not in (
            "read_document",
            "draft_note",
        ):
            raise ContractError("unsupported tool")
        tool = value["tool"]
        data = fields(
            value,
            {"tool", "resource", "revision"}
            | ({"text"} if tool == "draft_note" else set()),
        )
        if type(data["revision"]) is not int or not 0 <= data["revision"] <= 1_000_000:
            raise ContractError("invalid revision")
        text = bounded_text(data["text"]) if tool == "draft_note" else ""
        if tool == "draft_note" and not text.strip():
            raise ContractError("empty draft")
        return cls(tool, identifier(data["resource"]), data["revision"], text)


@dataclass(frozen=True)
class Approval:
    """Opaque authority-issued approval bound to exact caller, action and expiry; never serialized to reports."""

    nonce: str
    expires: int
    binding: str
    mac: str


class Authority:
    """Single-process approval issuer/verifier with bounded replay state; not a distributed identity service."""

    def __init__(self) -> None:
        """Generate an ephemeral MAC key; restarting invalidates all outstanding approvals."""
        self._key = secrets.token_bytes(32)
        self._spent: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def binding(context: Context, action: Action) -> str:
        """Bind caller, tenant, session, capabilities, policy revision and complete action arguments."""
        return digest({"context": context.__dict__, "action": action.__dict__})

    def signature(self, nonce: str, expires: int, binding: str) -> str:
        """MAC authority metadata; the key is never exposed to model adapters or reports."""
        return hmac.new(
            self._key, canonical([nonce, expires, binding]), hashlib.sha256
        ).hexdigest()

    def issue(self, context: Context, action: Action, now: int) -> Approval:
        """Trusted operator-only harness operation; issue a sixty-tick approval, not an AI authorization API."""
        nonce = secrets.token_hex(16)
        binding = self.binding(context, action)
        return Approval(
            nonce, now + 60, binding, self.signature(nonce, now + 60, binding)
        )

    def consume(
        self, approval: Approval | None, context: Context, action: Action, now: int
    ) -> bool:
        """Atomically verify and spend a valid approval once; invalid attempts do not consume it."""
        if approval is None:
            return False
        with self._lock:
            if not hmac.compare_digest(
                self.signature(approval.nonce, approval.expires, approval.binding),
                approval.mac,
            ):
                return False
            if (
                not now < approval.expires <= now + 60
                or approval.binding != self.binding(context, action)
            ):
                return False
            if approval.nonce in self._spent or len(self._spent) >= 1000:
                return False
            self._spent.add(approval.nonce)
            return True


@dataclass(frozen=True)
class Decision:
    """Safe metadata-only disposition; never includes prompts, draft contents, canaries or approvals."""

    verdict: str
    reason: str
    completed: bool
    effects: int = 0


def contains_canary(text: str) -> bool:
    """Match four known synthetic representations after NFKC/casefold; not a general DLP detector."""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return any(
        unicodedata.normalize("NFKC", value).casefold() in normalized
        for value in VARIANTS
    )


class Broker:
    """Complete mediation for one mock tenant resource; effects are counters, never network/file operations."""

    def __init__(self, context: Context, authority: Authority) -> None:
        """Initialize caller-bound dummy state; lock revision check and approval consumption together."""
        self.context = context
        self.authority = authority
        self.revision = 1
        self.effects = 0
        self._lock = threading.Lock()

    def execute(self, action: Action, approval: Approval | None, now: int) -> Decision:
        """Recheck scope, tenant/resource and current revision before every simulated read or draft."""
        try:
            payload = {
                "tool": action.tool,
                "resource": action.resource,
                "revision": action.revision,
            }
            if action.tool == "draft_note":
                payload["text"] = action.text
            Action.from_json(payload)
        except ContractError:
            return Decision("block", "invalid-action", False)
        with self._lock:
            scope = "read" if action.tool == "read_document" else "draft"
            if self.context.tenant != "tenant-a" or action.resource != "doc-a":
                return Decision("block", "resource-scope", False)
            if scope not in self.context.scopes:
                return Decision("block", "capability", False)
            if action.revision != self.revision:
                return Decision("block", "stale-resource", False)
            if contains_canary(action.text):
                return Decision("block", "canary", False)
            if scope == "draft":
                if not self.authority.consume(approval, self.context, action, now):
                    return Decision("review", "approval-required", False)
                self.effects += 1
                self.revision += 1
            return Decision("allow", "completed", True, self.effects)

    def handle(
        self, response: Any, approval: Approval | None = None, now: int = 100
    ) -> Decision:
        """Validate all untrusted output before any effect; accept at most one narrow tool call per response."""
        try:
            data = fields(response, {"answer", "citations", "actions"})
            answer = bounded_text(data["answer"])
            actions, citations = data["actions"], data["citations"]
            if not isinstance(actions, list) or len(actions) > 1:
                raise ContractError("one-action budget")
            if (
                not isinstance(citations, list)
                or len(citations) > 4
                or any(type(item) is not str for item in citations)
            ):
                raise ContractError("citation schema")
            action = Action.from_json(actions[0]) if actions else None
            if contains_canary(answer):
                return Decision("block", "canary", False)
            if any(item != "doc-a" for item in citations):
                return Decision("review", "unverified-citation", False)
            if citations and (
                self.context.tenant != "tenant-a" or "read" not in self.context.scopes
            ):
                return Decision("block", "citation-scope", False)
            if action is not None:
                return self.execute(action, approval, now)
            if not answer.strip() or not citations:
                return Decision("review", "missing-task-evidence", False)
            return Decision("allow", "accepted-text-ungraded", False)
        except (ContractError, TypeError):
            return Decision("block", "invalid-response", False)
