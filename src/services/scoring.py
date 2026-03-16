from typing import Sequence


def clip_score(x: float) -> float:
    return max(0.0, min(1.0, x))


def compute_final_score(
    ml_score: float,
    rule_score: float,
    reason_codes: Sequence[str] | None = None,
) -> float:
    score = 0.65 * ml_score + 0.35 * rule_score
    reason_codes = set(reason_codes or [])

    if "external_link" in reason_codes and "credential_request" in reason_codes:
        score += 0.10

    if "security_service_impersonation" in reason_codes and "money_transfer_push" in reason_codes:
        score += 0.10

    if "account_verification" in reason_codes and "urgency" in reason_codes:
        score += 0.06

    spam_only = reason_codes and reason_codes.issubset({
        "ad_promo",
        "contact_spam",
        "free_offer",
        "job_spam",
        "manager_contact",
        "suspicious_chars",
        "many_digits",
    })
    if spam_only:
        score = min(score, 0.72)

    return round(clip_score(score), 4)


def resolve_risk_level(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"