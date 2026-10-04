"""Request context for policy evaluation (``pront.md`` §19).

§19 says policy must consider *tenant, user, group, device, URL, domain,
category, score, confidence, content type, time and zone*. The rule engine has
always supported arbitrary dotted fields - what was missing is the **context**
those fields resolve against. :class:`app.core.policy.PolicyEngine.build_context`
produced only what a classification result knows (verdict, score, media type),
so a rule on ``zone`` or ``groups`` silently evaluated to ``False`` and never
matched. A policy that appears to work but never fires is worse than one that
is visibly absent.

This module builds that context from the three places the information exists:
the authenticated principal (§35), the request headers an NGFW/proxy sets, and
the clock. It is a pure function of its inputs - no globals, no I/O - so it is
trivially testable and safe to call from any transport.

Time is exposed as *derived booleans and numbers* rather than as a new operator:
``time.hour``, ``time.weekday``, ``time.night`` and ``time.weekend``. A policy
then reads as ordinary declarative rules (``{"field": "time.night", "operator":
"==", "value": true}``) instead of needing a bespoke ``during_business_hours()``
callable, which would break the "rules are data, not code" property that makes
policy files reviewable and diffable.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, Iterable, List, Optional

#: Header names an NGFW, Squid or load balancer commonly sets. All are optional:
#: a deployment that sets none still gets a valid (just thinner) context.
HEADER_TENANT = "x-tenant-id"
HEADER_USER = "x-user-id"
HEADER_GROUPS = "x-user-groups"
HEADER_DEVICE = "x-device-id"
HEADER_ZONE = "x-zone"
HEADER_URL = "x-forwarded-url"
HEADER_HOST = "x-forwarded-host"

#: Business hours used to derive ``time.business_hours``. Configurable per
#: deployment in a real rollout; these are the defaults the name implies.
BUSINESS_HOUR_START = 8
BUSINESS_HOUR_END = 18


def _split_groups(value: Optional[str]) -> List[str]:
    """Parse a group header into a normalised list.

    Accepts comma, semicolon, pipe and space separated forms, because different
    proxies emit different ones and a group silently not parsing means a rule
    silently not matching.
    """
    if not value:
        return []
    normalised = value.replace(";", ",").replace("|", ",").replace(",", " ")
    return sorted({part.strip().lower() for part in normalised.split() if part.strip()})


def time_facet(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """Derive the §19 ``time`` facet from a timestamp.

    Every value is computed from a single ``now`` so a rule cannot straddle a
    minute boundary part-way through an evaluation.
    """
    moment = now or _dt.datetime.now()
    hour = moment.hour
    # Python's weekday() is Monday=0; kept as-is because that is the convention
    # operators already know from cron, and the field is documented as such.
    weekday = moment.weekday()
    return {
        "hour": hour,
        "weekday": weekday,
        "is_weekend": weekday >= 5,
        "business_hours": BUSINESS_HOUR_START <= hour < BUSINESS_HOUR_END,
        # "Night" is the window where a stricter posture usually makes sense.
        "night": hour >= 22 or hour < 6,
        "hour_24": f"{hour:02d}",
        "date": moment.date().isoformat(),
    }


def build_request_context(
    *,
    tenant_id: str = "",
    user_id: str = "",
    groups: Optional[Iterable[str]] = None,
    device_id: str = "",
    zone: str = "",
    url: str = "",
    domain: str = "",
    category: str = "",
    now: Optional[_dt.datetime] = None,
) -> Dict[str, Any]:
    """Assemble the §19 dimensions into a mapping usable as a rule context.

    Groups are stored both as a list and as a comma-joined string so a rule can
    use either ``groups contains admin`` (membership) or an exact
    ``groups_csv == "admin,staff"`` without the policy author having to know
    which representation is in play.
    """
    resolved = sorted(
        {str(group).strip().lower() for group in (groups or []) if str(group).strip()}
    )
    return {
        "tenant_id": tenant_id or "",
        "user_id": user_id or "",
        "groups": resolved,
        "groups_csv": ",".join(resolved),
        "device_id": device_id or "",
        "zone": zone or "",
        "url": url or "",
        "domain": domain or "",
        "category": category or "",
        "time": time_facet(now),
    }


def context_from_headers(
    headers: Any,
    *,
    tenant_id: str = "",
    user_id: str = "",
    groups: Optional[Iterable[str]] = None,
    url: str = "",
    domain: str = "",
    now: Optional[_dt.datetime] = None,
) -> Dict[str, Any]:
    """Build the context from request headers, with explicit arguments winning.

    Explicit arguments override headers on purpose: the authenticated principal
    is a stronger statement of identity than anything a proxy can assert, so a
    client-supplied ``X-User-Id`` must never outrank it (§35).

    .. warning::
       **Header-supplied dimensions are advisory and spoofable.** Anyone who can
       reach the engine can set ``X-User-Groups``, ``X-Zone`` or ``X-Device-Id``.
       They are safe for *observability* and for rules that only ever make a
       decision *stricter* (e.g. "Kiosk zone blocks NSFW"). They are **not** safe
       for rules that relax enforcement based on an asserted group, because
       ``X-User-Groups: admin`` would satisfy one.

       Authorisation is unaffected: :mod:`app.core.security` derives permissions
       from the API key, never from these headers. Treat a group-based
       exemption as requiring a signed assertion (mTLS subject, JWT claim) rather
       than a plain header, and strip these headers at the ingress if the NGFW
       does not set them itself.
    """

    def header(name: str) -> str:
        try:
            return (headers.get(name) or "").strip()
        except Exception:  # noqa: BLE001 - a stub mapping in tests
            return ""

    merged_groups = set(_split_groups(header(HEADER_GROUPS)))
    merged_groups.update(
        str(group).strip().lower() for group in (groups or []) if str(group).strip()
    )

    resolved_domain = domain or header(HEADER_HOST)
    resolved_url = url or header(HEADER_URL)
    if resolved_domain and "://" in resolved_domain:
        from urllib.parse import urlsplit

        resolved_domain = urlsplit(resolved_domain).hostname or resolved_domain
    if not resolved_domain and resolved_url and "://" in resolved_url:
        # Derive the domain from the URL when no host header was supplied;
        # §19 lists both as separate dimensions and a policy on `domain` should
        # work whether the caller gave one or the other.
        from urllib.parse import urlsplit

        resolved_domain = urlsplit(resolved_url).hostname or ""

    return build_request_context(
        tenant_id=tenant_id or header(HEADER_TENANT),
        user_id=user_id or header(HEADER_USER),
        groups=sorted(merged_groups),
        device_id=header(HEADER_DEVICE),
        zone=header(HEADER_ZONE),
        url=resolved_url,
        domain=resolved_domain,
        now=now,
    )


__all__ = [
    "BUSINESS_HOUR_END",
    "BUSINESS_HOUR_START",
    "HEADER_DEVICE",
    "HEADER_GROUPS",
    "HEADER_HOST",
    "HEADER_TENANT",
    "HEADER_URL",
    "HEADER_USER",
    "HEADER_ZONE",
    "build_request_context",
    "context_from_headers",
    "time_facet",
]
