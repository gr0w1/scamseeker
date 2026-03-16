from typing import Iterable


def build_recommendations(
    risk_level: str,
    dominant_category: str | None,
    reason_codes: Iterable[str] | None = None,
) -> list[str]:
    reason_codes = set(reason_codes or [])
    recommendations: list[str] = []

    if risk_level == "high":
        recommendations.extend([
            "Не переходите по ссылкам из сообщения.",
            "Не вводите пароль, коды подтверждения и данные карты.",
            "Проверьте отправителя через официальный сайт или приложение сервиса.",
        ])
    elif risk_level == "medium":
        recommendations.extend([
            "Перепроверьте отправителя и смысл сообщения.",
            "Не открывайте ссылки и вложения, пока не убедитесь в подлинности.",
            "Сравните сообщение с официальными уведомлениями сервиса.",
        ])
    else:
        recommendations.extend([
            "Явных критических признаков немного, но всё равно сохраняйте осторожность.",
            "Не передавайте личные данные без дополнительной проверки.",
        ])

    if "external_link" in reason_codes or "shortener_link" in reason_codes:
        recommendations.append("Если нужно открыть сайт, лучше введите адрес вручную в браузере.")

    if "credential_request" in reason_codes or "card_details_request" in reason_codes:
        recommendations.append("Никому не сообщайте логин, пароль, CVV/CVC и коды из SMS.")

    if dominant_category == "phishing":
        recommendations.append("Для входа в аккаунт открывайте сервис только вручную, а не по ссылке из сообщения.")
    elif dominant_category == "financial":
        recommendations.append("Любые операции с деньгами перепроверьте через банк или официальный сервис.")
    elif dominant_category == "social_engineering":
        recommendations.append("Не поддавайтесь на срочность и давление — сначала остановитесь и перепроверьте факты.")

    seen = set()
    unique: list[str] = []
    for item in recommendations:
        if item not in seen:
            unique.append(item)
            seen.add(item)

    return unique[:5]