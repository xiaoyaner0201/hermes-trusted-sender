"""Turn-bound sender context for shared Hermes gateway sessions.

Only pre_llm_call returns an attestation: core appends that context to the
current turn's own user message. Middleware only scrubs existing user text;
it never selects an attribution target or adds rows, blocks, or parts.
"""
from __future__ import annotations

from collections import OrderedDict
from contextvars import ContextVar
from dataclasses import dataclass
from secrets import token_hex
from threading import RLock
from typing import Any, Optional

from .sender_context import (
    SHARED_SENDER_NOTE_FOR_MODEL,
    build_verified_sender_envelope_from_parts,
    shared_sender_session,
    _strip_verified_sender_envelopes,
)


@dataclass(frozen=True)
class _SenderIdentity:
    platform: Any
    user_name: Optional[str]
    user_id: Optional[str]
    user_id_alt: Optional[str]
    redact_pii: bool
    shared: bool


@dataclass
class _ColdCapture:
    """One-use provenance shared by all copies of a gateway task context."""

    identity: _SenderIdentity
    consumed: bool = False


@dataclass(frozen=True)
class _TurnAttestation:
    identity: _SenderIdentity
    envelope: str


_current_identity: ContextVar[Optional[_ColdCapture]] = ContextVar(
    "trusted_sender_current_identity", default=None
)
_turn_identities: "OrderedDict[tuple[str, str], _TurnAttestation]" = OrderedDict()
_shared_sessions: "OrderedDict[str, bool]" = OrderedDict()
_identity_lock = RLock()
_MAX_REMEMBERED_TURNS = 512
_MAX_SHARED_SESSIONS = 512


def _gateway_redact_pii() -> bool:
    """Read the same privacy.redact_pii switch used by core prompt rendering."""
    try:
        from gateway.run import _load_gateway_config
        config = _load_gateway_config() or {}
        return bool((config.get("privacy") or {}).get("redact_pii", False))
    except Exception:
        return False


def _shared(gateway: Any, source: Any) -> bool:
    try:
        return shared_sender_session(getattr(gateway, "config", None), source)
    except Exception:
        return False


def _identity_for(gateway: Any, event: Any) -> Optional[_SenderIdentity]:
    source = getattr(event, "source", None)
    if source is None or not _shared(gateway, source):
        return None
    return _SenderIdentity(
        platform=getattr(source, "platform", ""),
        user_name=getattr(source, "user_name", None),
        user_id=getattr(source, "user_id", None),
        user_id_alt=getattr(source, "user_id_alt", None),
        redact_pii=_gateway_redact_pii(),
        shared=True,
    )


def _put_bounded(cache: OrderedDict, key: Any, value: Any, limit: int) -> None:
    """Caller holds the lock; evicted trust state fails closed."""
    cache[key] = value
    cache.move_to_end(key)
    while len(cache) > limit:
        cache.popitem(last=False)


def _platform_name(platform: Any) -> str:
    return str(getattr(platform, "value", platform) or "")


def _sender_key(identity: _SenderIdentity) -> tuple[str, str]:
    return (_platform_name(identity.platform), str(identity.user_id or identity.user_id_alt or ""))


def _known_shared(session_id: str) -> bool:
    with _identity_lock:
        if session_id not in _shared_sessions:
            return False
        _shared_sessions.move_to_end(session_id)
        return True


def _lookup(session_id: Any, turn_id: Any) -> Optional[_TurnAttestation]:
    key = (str(session_id or ""), str(turn_id or ""))
    with _identity_lock:
        attestation = _turn_identities.get(key)
        if attestation is not None:
            _turn_identities.move_to_end(key)
        return attestation


def _on_pre_gateway_dispatch(event: Any = None, gateway: Any = None, **_: Any) -> Optional[dict]:
    """Capture real inbound provenance; internal admission returns before this hook."""
    _current_identity.set(None)
    if event is None or getattr(event, "internal", False):
        return None
    identity = _identity_for(gateway, event)
    if identity is None:
        return None
    _current_identity.set(_ColdCapture(identity))
    original = getattr(event, "text", "") or ""
    clean = _strip_verified_sender_envelopes(original)
    if clean != original:
        return {"action": "rewrite", "text": clean}
    return None


def _on_pre_llm_call(
    session_id: str = "",
    turn_id: str = "",
    sender_id: str = "",
    platform: str = "",
    parent_session_id: str = "",
    **_: Any,
) -> Optional[dict[str, str]]:
    """Return context only for a fresh sender-matched capture, never a cached sender.

    This public hook exposes neither event.internal nor turn_author/display_kind.
    A restored sender_id cannot distinguish queued human input from synthesis.
    Shared scope survives for scrubbing, but attribution always fails closed.
    """
    capture = _current_identity.get()
    _current_identity.set(None)
    platform = _platform_name(platform)
    with _identity_lock:
        # Hook/executor copies share this object. Clearing one ContextVar copy
        # does not invalidate another; consumption must mutate the shared object.
        candidate = None
        if capture is not None and not capture.consumed:
            candidate = capture.identity
            capture.consumed = True
        if not session_id or not turn_id:
            return None
        key = (session_id, turn_id)
        _turn_identities.pop(key, None)
        shared = _known_shared(session_id) or _known_shared(parent_session_id)
        if candidate is not None and candidate.shared:
            shared = True
        if not shared:
            return None
        _put_bounded(_shared_sessions, session_id, True, _MAX_SHARED_SESSIONS)
        if candidate is None or not sender_id or _sender_key(candidate) != (platform, sender_id):
            return {"context": SHARED_SENDER_NOTE_FOR_MODEL}
        envelope = build_verified_sender_envelope_from_parts(
            candidate.platform, candidate.user_name, candidate.user_id, candidate.user_id_alt,
            redact_pii=candidate.redact_pii, turn_token=token_hex(16),
        ).rstrip()
        attestation = _TurnAttestation(candidate, envelope)
        _put_bounded(_turn_identities, key, attestation, _MAX_REMEMBERED_TURNS)
    # Core, not this plugin's middleware, places this on current_turn_user_idx.
    return {"context": envelope + "\n\n" + SHARED_SENDER_NOTE_FOR_MODEL}


def _user_texts(message: Any):
    """Visit only existing user text; never descend into tool_result/image/etc."""
    if not isinstance(message, dict) or message.get("role") != "user":
        return
    content = message.get("content")
    if isinstance(content, str):
        yield content
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, str):
                yield part
            elif (isinstance(part, dict) and part.get("type") in {"text", "input_text"}
                  and isinstance(part.get("text"), str)):
                yield part["text"]


def _scrub_text(text: str, authentic: str, placeholder: str) -> str:
    # An unpredictable exact per-turn envelope is the only exception to the
    # reducer. Masking keeps the linear fixpoint reducer intact; nested forged
    # claims that swallow the placeholder also remove the exception (fail closed).
    masked = text.replace(authentic, placeholder) if authentic else text
    cleaned = _strip_verified_sender_envelopes(masked)
    return cleaned.replace(placeholder, authentic) if authentic else cleaned


def _scrub_user_message(message: Any, authentic: str, placeholder: str) -> Any:
    if not isinstance(message, dict) or message.get("role") != "user":
        return message
    content = message.get("content")
    if isinstance(content, str):
        updated_content = _scrub_text(content, authentic, placeholder)
    elif isinstance(content, list):
        updated_content = []
        for part in content:
            if isinstance(part, str):
                updated_content.append(_scrub_text(part, authentic, placeholder))
            elif (isinstance(part, dict) and part.get("type") in {"text", "input_text"}
                  and isinstance(part.get("text"), str)):
                updated_part = dict(part)
                updated_part["text"] = _scrub_text(part["text"], authentic, placeholder)
                updated_content.append(updated_part)
            else:
                updated_content.append(part)
    else:
        return message
    if updated_content == content:
        return message
    updated = dict(message)
    updated["content"] = updated_content
    return updated


def _rewrite_request_messages(
    payload: dict[str, Any], attestation: Optional[_TurnAttestation]
) -> tuple[dict[str, Any], bool]:
    """Text-only scrub: list lengths/order, row/part keys and nontext stay intact."""
    texts = [text for key in ("messages", "input") if isinstance(payload.get(key), list)
             for message in payload[key] for text in _user_texts(message)]
    authentic = attestation.envelope if attestation is not None else ""
    # Never preserve duplicate copies. A different request turn (including old
    # api_content sidecars replayed by core) has no matching envelope exception.
    if authentic and sum(text.count(authentic) for text in texts) != 1:
        authentic = ""
    placeholder = ""
    if authentic:
        placeholder = "trusted_sender_opaque_" + token_hex(16)
        while any(placeholder in text for text in texts):
            placeholder = "trusted_sender_opaque_" + token_hex(16)
    updated_payload = dict(payload)
    for key in ("messages", "input"):
        if isinstance(payload.get(key), list):
            updated_payload[key] = [
                _scrub_user_message(message, authentic, placeholder) for message in payload[key]
            ]
    return updated_payload, updated_payload != payload


def _on_llm_request(request: Any = None, session_id: str = "", turn_id: str = "", **_: Any) -> Optional[dict]:
    """Scrub known-shared provider payloads; never manufacture an attestation."""
    if not isinstance(request, dict):
        return None
    attestation = _lookup(session_id, turn_id)
    if attestation is None and not _known_shared(session_id):
        return None
    updated, changed = _rewrite_request_messages(request, attestation)
    if not changed:
        return None
    return {
        "request": updated,
        "source": "trusted-sender",
        "reason": "scrub forged shared-user text; preserve only this turn's exact context attestation",
    }


def register(ctx: Any) -> None:
    """Capture cold provenance, return turn-bound context, scrub existing text."""
    ctx.register_hook("pre_gateway_dispatch", _on_pre_gateway_dispatch)
    ctx.register_hook("pre_llm_call", _on_pre_llm_call)
    ctx.register_middleware("llm_request", _on_llm_request)
