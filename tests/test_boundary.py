"""Jason Stys: real broker state, exact approval integrity, replay, concurrency and output-shape regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: draft — line 55
# definition: test_single_use_and_concurrent_revision — line 60
# variable: authority — line 62
# variable: context — line 62
# variable: action — line 63
# variable: broker — line 63
# variable: _ — line 64
# variable: approvals — line 64
# variable: pool — line 65
# variable: decisions — line 66
# parameter: token — line 67
# variable: result — line 69
# variable: token — line 73
# variable: token — line 76
# definition: test_approval_binding_and_replay — line 80
# variable: action — line 82
# variable: authority — line 82
# variable: context — line 82
# variable: token — line 83
# variable: changed — line 84
# definition: test_approval_capacity_fail_closed — line 104
# variable: action — line 106
# variable: authority — line 106
# variable: context — line 106
# variable: first — line 107
# variable: _ — line 109
# definition: test_action_schema — line 130
# parameter: payload — line 130
# definition: test_direct_broker_boundaries — line 136
# variable: authority — line 138
# variable: broker — line 139
# variable: response — line 151
# definition: test_canary_and_no_approval — line 174
# parameter: text — line 174
# variable: broker — line 176
# variable: result — line 177
# END CODE MAP

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aisec.boundary import CANARY, Action, Authority, Broker, Context, contains_canary
from aisec.contracts import ContractError


def draft() -> Action:
    """Return the one permitted mutation fixture; no operating-system or external state is touched."""
    return Action("draft_note", "doc-a", 1, "Reviewed maintenance note.")


def test_single_use_and_concurrent_revision() -> None:
    """Two concurrent approved drafts for revision one cannot both change dummy state."""
    context, authority = Context(), Authority()
    broker, action = Broker(context, authority), draft()
    approvals = [authority.issue(context, action, 100) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        decisions = list(
            pool.map(lambda token: broker.execute(action, token, 100), approvals)
        )
    assert sum(result.completed for result in decisions) == 1
    assert broker.effects == 1 and broker.revision == 2
    assert broker.execute(action, approvals[0], 100).reason == "stale-resource"
    assert (
        sum(authority.consume(token, context, action, 100) for token in approvals) == 1
    )
    assert all(
        not authority.consume(token, context, action, 100) for token in approvals
    )


def test_approval_binding_and_replay() -> None:
    """Every caller, capability, target, action, expiry and MAC dimension is independently enforced."""
    context, authority, action = Context(), Authority(), draft()
    token = authority.issue(context, action, 100)
    for changed in [
        replace(context, tenant="tenant-b"),
        replace(context, user="user-b"),
        replace(context, session="session-b"),
        replace(context, scopes=("read",)),
        replace(context, policy_revision=2),
    ]:
        assert not authority.consume(token, changed, action, 100)
    assert not authority.consume(token, context, replace(action, text="different"), 100)
    assert not authority.consume(replace(token, mac="0" * 64), context, action, 100)
    assert not authority.consume(
        replace(token, nonce="different"), context, action, 100
    )
    assert not authority.consume(token, context, action, 160)
    assert not authority.consume(token, context, action, 99)
    assert authority.consume(token, context, action, 100)
    assert not authority.consume(token, context, action, 100)
    assert not authority.consume(None, context, action, 100)


def test_approval_capacity_fail_closed() -> None:
    """A full single-process replay ledger does not evict old entries and re-enable spent approvals."""
    context, authority, action = Context(), Authority(), draft()
    first = authority.issue(context, action, 100)
    assert authority.consume(first, context, action, 100)
    for _ in range(999):
        assert authority.consume(
            authority.issue(context, action, 100), context, action, 100
        )
    assert not authority.consume(
        authority.issue(context, action, 100), context, action, 100
    )
    assert not authority.consume(first, context, action, 100)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"tool": "fetch_url"},
        {"tool": "read_document", "resource": "doc-a", "revision": -1},
        {"tool": "read_document", "resource": "doc-a", "revision": 1000001},
        {"tool": "draft_note", "resource": "doc-a", "revision": 1, "text": ""},
    ],
    ids=["type", "unknown", "negative", "revision-limit", "blank"],
)
def test_action_schema(payload: Any) -> None:
    """Reject malformed actions before reaching authorization or approval checks."""
    with pytest.raises(ContractError):
        Action.from_json(payload)


def test_direct_broker_boundaries() -> None:
    """The typed execution API also rejects unsupported actions, foreign tenant context and leaked draft text."""
    authority = Authority()
    broker = Broker(Context(), authority)
    assert (
        broker.execute(Action("shell", "doc-a", 1), None, 100).reason
        == "invalid-action"
    )
    assert (
        Broker(Context(tenant="tenant-b"), authority)
        .execute(Action("read_document", "doc-a", 1), None, 100)
        .reason
        == "resource-scope"
    )
    assert broker.execute(replace(draft(), text=CANARY), None, 100).reason == "canary"
    response = {"answer": "Summary.", "citations": ["doc-a"], "actions": []}
    assert (
        Broker(Context(scopes=()), authority).handle(response).reason
        == "citation-scope"
    )
    assert (
        Broker(Context(tenant="tenant-b"), authority).handle(response).reason
        == "citation-scope"
    )
    assert (
        broker.handle(response).verdict == "allow"
        and not broker.handle(response).completed
    )
    assert broker.handle({**response, "citations": [1]}).reason == "invalid-response"
    assert (
        broker.handle({**response, "citations": ["doc-a"] * 5}).reason
        == "invalid-response"
    )
    assert broker.handle({**response, "answer": None}).reason == "invalid-response"


@given(st.text(max_size=100))
@settings(max_examples=200, deadline=None)
def test_canary_and_no_approval(text: str) -> None:
    """Mutation/property test: arbitrary draft contents never create effects without a valid exact approval."""
    broker = Broker(Context(), Authority())
    result = broker.handle(
        {
            "answer": "",
            "citations": [],
            "actions": [
                {"tool": "draft_note", "resource": "doc-a", "revision": 1, "text": text}
            ],
        }
    )
    assert (
        not result.completed
        and broker.effects == 0
        and result.verdict in ("block", "review")
    )
    assert contains_canary("prefix " + CANARY + " suffix")
    assert not contains_canary("A harmless maintenance note.")
