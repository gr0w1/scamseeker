from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern


@dataclass(frozen=True)
class Rule:
    code: str
    title: str
    description: str
    category: str
    severity: str
    weight: float
    pattern: Pattern[str]
    label: Optional[str] = None


def _rx(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.UNICODE)


RULES: List[Rule] = [
    Rule(
        code="external_link",
        title="Есть ссылка",
        description="Сообщение содержит ссылку, которая может вести на поддельный или вредоносный сайт.",
        category="phishing",
        severity="high",
        weight=0.18,
        label="Подозрительная ссылка",
        pattern=_rx(r"(https?://[^\s]+|www\.[^\s]+|t\.me/[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+)")
    ),
    Rule(
        code="shortener_link",
        title="Ссылка-сокращатель",
        description="Использование сокращённой ссылки может скрывать настоящий адрес назначения.",
        category="phishing",
        severity="high",
        weight=0.12,
        label="Сокращённая ссылка",
        pattern=_rx(r"\b(bit\.ly|tinyurl\.com|clck\.ru|goo\.gl|t\.co|cutt\.ly|is\.gd)/?[^\s]*")
    ),
    Rule(
        code="masked_domain",
        title="Подозрительный домен",
        description="В сообщении есть доменоподобный фрагмент, который стоит проверить вручную.",
        category="phishing",
        severity="medium",
        weight=0.08,
        label="Подозрительный домен",
        pattern=_rx(r"\b[a-z0-9-]+\.(ru|com|net|org|site|online|xyz|top|click|icu|shop)\b")
    ),
    Rule(
        code="fake_brand_domain_hint",
        title="Похоже на маскировку под бренд",
        description="Есть признаки имитации известного сервиса через домен или название.",
        category="phishing",
        severity="high",
        weight=0.14,
        label="Имитация бренда",
        pattern=_rx(r"\b(sber|sb?rbank|gosuslugi|gos-uslugi|nalog|vtb|alfa|alpha|ozon|wb|wildberries|avito|yandex|pochta|qiwi|paypal)[a-z0-9-]*\.(ru|com|site|online|xyz)\b")
    ),
    Rule(
        code="urgency",
        title="Давление срочностью",
        description="Сообщение подталкивает к немедленному действию.",
        category="social_engineering",
        severity="medium",
        weight=0.12,
        label="Срочность",
        pattern=_rx(r"\b(срочно|немедленно|прямо сейчас|как можно скорее|без промедления|urgent|сегодня до конца дня|в течение \d+ (минут|часов))\b")
    ),
    Rule(
        code="threat_consequence",
        title="Угроза последствий",
        description="Текст запугивает блокировкой, штрафом, потерей доступа или другими санкциями.",
        category="social_engineering",
        severity="high",
        weight=0.16,
        label="Угроза последствий",
        pattern=_rx(r"\b(иначе|в противном случае|будет заблокирован|аккаунт будет заблокирован|доступ будет ограничен|ваша карта заблокирована|штраф|пени|судебн|долг|задолженность)\b")
    ),
    Rule(
        code="time_limit",
        title="Есть жёсткий срок",
        description="Указан короткий срок, чтобы заставить пользователя действовать быстро.",
        category="social_engineering",
        severity="medium",
        weight=0.10,
        label="Ограничение по времени",
        pattern=_rx(r"\b(осталось \d+ (минут|часа|часов|дней)|последний шанс|до \d{1,2}[:.]\d{2}|до конца дня|в течение суток)\b")
    ),
    Rule(
        code="credential_request",
        title="Запрос данных входа",
        description="В сообщении есть признаки запроса логина, пароля или подтверждения входа.",
        category="phishing",
        severity="high",
        weight=0.20,
        label="Запрос учётных данных",
        pattern=_rx(r"\b(логин|парол[ьяе]?|password|pin[- ]?код|пин[- ]?код|код подтверждения|смс[- ]?код|одноразовый код|otp|cvv|cvc)\b")
    ),
    Rule(
        code="account_verification",
        title="Просьба подтвердить аккаунт",
        description="Сообщение просит подтвердить аккаунт, личность или устройство.",
        category="phishing",
        severity="high",
        weight=0.18,
        label="Подтверждение аккаунта",
        pattern=_rx(r"\b(подтвердите аккаунт|подтвердите личность|подтвердите вход|подтвердите устройство|пройдите проверку|верифицируйте аккаунт|проверка личности|идентификация)\b")
    ),
    Rule(
        code="login_action",
        title="Призыв войти в аккаунт",
        description="Сообщение склоняет перейти в аккаунт, пройти авторизацию или восстановление доступа.",
        category="phishing",
        severity="medium",
        weight=0.10,
        label="Призыв к авторизации",
        pattern=_rx(r"\b(войдите в аккаунт|выполните вход|авторизуйтесь|восстановите доступ|сбросьте пароль|смените пароль)\b")
    ),
    Rule(
        code="bank_context",
        title="Банковский контекст",
        description="Упоминаются банковские операции, карты или переводы.",
        category="financial",
        severity="medium",
        weight=0.10,
        label="Банковская тематика",
        pattern=_rx(r"\b(банк|карта|карточка|сч[её]т|перевод|оплата|плат[её]ж|списание|зачисление|баланс|кошел[её]к|реквизиты)\b")
    ),
    Rule(
        code="card_details_request",
        title="Запрос реквизитов карты",
        description="Текст просит предоставить данные банковской карты.",
        category="phishing",
        severity="high",
        weight=0.22,
        label="Запрос данных карты",
        pattern=_rx(r"\b(номер карты|данные карты|реквизиты карты|cvv|cvc|срок действия карты|тр[её]хзначный код)\b")
    ),
    Rule(
        code="security_service_impersonation",
        title="Имитация службы безопасности",
        description="Мошенники часто выдают себя за банк, службу безопасности или сотрудника поддержки.",
        category="scam",
        severity="high",
        weight=0.18,
        label="Имитация службы безопасности",
        pattern=_rx(r"\b(служба безопасности|сотрудник банка|отдел безопасности|финансовый мониторинг|антифрод|служба поддержки банка)\b")
    ),
    Rule(
        code="money_transfer_push",
        title="Давление на перевод денег",
        description="Есть призыв перевести деньги, оплатить или срочно выполнить операцию.",
        category="scam",
        severity="high",
        weight=0.18,
        label="Призыв к переводу",
        pattern=_rx(r"\b(переведите|срочно оплатите|оплатите сейчас|внесите оплату|подтвердите перевод|отправьте деньги|выполните перевод)\b")
    ),
    Rule(
        code="reward_bait",
        title="Приманка выгодой",
        description="Сообщение обещает приз, выплату или другую неожиданную выгоду.",
        category="scam",
        severity="medium",
        weight=0.12,
        label="Обещание выгоды",
        pattern=_rx(r"\b(вы выиграли|вам одобрен[ао]?|начислена выплата|положена компенсация|подарок|бонус|приз|розыгрыш|лотерея|вознаграждение|скидка \d+%|кэшбэк)\b")
    ),
    Rule(
        code="free_offer",
        title="Слишком щедрое предложение",
        description="Подозрительно выгодное предложение может быть приманкой.",
        category="spam",
        severity="medium",
        weight=0.08,
        label="Слишком выгодное предложение",
        pattern=_rx(r"\b(бесплатно|даром|без вложений|без опыта|гарантированный доход|легкие деньги|быстрый заработок)\b")
    ),
    Rule(
        code="job_spam",
        title="Подозрительное предложение работы",
        description="Такие объявления часто используются в мошеннических и спам-рассылках.",
        category="spam",
        severity="medium",
        weight=0.10,
        label="Спам с работой",
        pattern=_rx(r"\b(удал[её]нн(ая|ую|ой)|работа на дому|подработка|доход от \d+|доход \d+ в день|без опыта|гибкий график|нужны сотрудники)\b")
    ),
    Rule(
        code="manager_contact",
        title="Перевод общения в мессенджер",
        description="Спам и мошенники часто уводят общение в Telegram или WhatsApp.",
        category="spam",
        severity="medium",
        weight=0.09,
        label="Перевод в мессенджер",
        pattern=_rx(r"\b(напишите в telegram|пишите в тг|свяжитесь в whatsapp|перейдите в telegram|ответьте менеджеру)\b")
    ),
    Rule(
        code="delivery_issue",
        title="Проблема с доставкой или заказом",
        description="Под видом доставки злоумышленники часто рассылают фишинговые сообщения.",
        category="phishing",
        severity="medium",
        weight=0.11,
        label="Проблема с заказом",
        pattern=_rx(r"\b(посылка|доставка|заказ|получение|трек[- ]?номер|курьер|неудачная доставка|оформите повторную доставку)\b")
    ),
    Rule(
        code="marketplace_brand",
        title="Упоминание популярного сервиса",
        description="Использование бренда маркетплейса или сервиса может быть частью подделки.",
        category="phishing",
        severity="medium",
        weight=0.08,
        label="Известный бренд",
        pattern=_rx(r"\b(ozon|вайлдберриз|wildberries|авито|avito|яндекс|yandex|сбер|сбербанк|госуслуги|почта россии)\b")
    ),
    Rule(
        code="gov_fear",
        title="Запугивание госорганами",
        description="Сообщение апеллирует к налогам, штрафам, повесткам или госуслугам.",
        category="social_engineering",
        severity="high",
        weight=0.16,
        label="Запугивание официальными структурами",
        pattern=_rx(r"\b(госуслуги|налоговая|фнс|мвд|судебн(ый|ая)|штраф|повестка|исполнительное производство|задолженность|арест счета)\b")
    ),
    Rule(
        code="trust_pressure",
        title="Манипуляция доверием",
        description="Текст пытается заставить довериться отправителю без проверки.",
        category="social_engineering",
        severity="medium",
        weight=0.08,
        label="Манипуляция доверием",
        pattern=_rx(r"\b(это безопасно|не волнуйтесь|все официально|мы из поддержки|мы вам поможем|это проверка безопасности)\b")
    ),
    Rule(
        code="friend_emergency",
        title="Сценарий срочной помощи",
        description="Просьбы срочно помочь деньгами или кодом часто бывают признаком взлома аккаунта.",
        category="scam",
        severity="high",
        weight=0.18,
        label="Срочная просьба о помощи",
        pattern=_rx(r"\b(срочно займи|срочно переведи|нужна помощь деньгами|пришли код|скинь код|одолжи|выручай)\b")
    ),
    Rule(
        code="ad_promo",
        title="Рекламный стиль",
        description="Текст похож на массовую рекламную рассылку.",
        category="spam",
        severity="low",
        weight=0.06,
        label="Рекламная подача",
        pattern=_rx(r"\b(акция|спецпредложение|только сегодня|выгодное предложение|лучшие цены|успейте купить|скидки|распродажа)\b")
    ),
    Rule(
        code="contact_spam",
        title="Навязчивый призыв к контакту",
        description="Сообщение активно подталкивает сразу написать или позвонить.",
        category="spam",
        severity="low",
        weight=0.05,
        label="Навязчивый призыв",
        pattern=_rx(r"\b(звоните|пишите прямо сейчас|оставьте заявку|жмите|нажмите|переходите)\b")
    ),
    Rule(
        code="many_digits",
        title="Много цифр",
        description="В тексте есть длинные числовые фрагменты, что может быть связано с кодами, заказами или реквизитами.",
        category="financial",
        severity="low",
        weight=0.04,
        label="Длинная числовая последовательность",
        pattern=_rx(r"\b\d{4,}\b")
    ),
    Rule(
        code="code_wording",
        title="Упоминание кода",
        description="Текст содержит лексику, связанную с кодом подтверждения или доступом.",
        category="phishing",
        severity="medium",
        weight=0.10,
        label="Код подтверждения",
        pattern=_rx(r"\b(код из смс|код подтверждения|секретный код|одноразовый пароль|не сообщайте код)\b")
    ),
    Rule(
        code="suspicious_chars",
        title="Маскировка символами",
        description="Подозрительное оформление может использоваться для обхода фильтров.",
        category="spam",
        severity="low",
        weight=0.04,
        label="Подозрительное оформление",
        pattern=_rx(r"([!]{2,}|[?]{2,}|руб\.?|₽|\$\$+|№)")
    ),
]


def _severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(severity, 1)


def _clip_score(x: float) -> float:
    return max(0.0, min(1.0, x))


def _merge_overlapping(items: List[Dict], text: str) -> List[Dict]:
    if not items:
        return []

    items = sorted(items, key=lambda x: (x["start"], x["end"], -_severity_rank(x["severity"])))
    merged = [items[0].copy()]

    for cur in items[1:]:
        prev = merged[-1]
        if cur["start"] <= prev["end"]:
            if _severity_rank(cur["severity"]) > _severity_rank(prev["severity"]) or cur["score"] > prev["score"]:
                prev["label"] = cur["label"]
                prev["reason_code"] = cur["reason_code"]
                prev["severity"] = cur["severity"]
                prev["score"] = max(prev["score"], cur["score"])
                prev["category"] = cur["category"]

            prev["end"] = max(prev["end"], cur["end"])
            prev["text"] = text[prev["start"]:prev["end"]]
        else:
            merged.append(cur.copy())

    return merged


def detect_rule_highlights(text: str, merge: bool = True, limit: int = 20) -> List[Dict]:
    highlights: List[Dict] = []

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            highlights.append({
                "start": match.start(),
                "end": match.end(),
                "text": text[match.start():match.end()],
                "score": round(rule.weight, 4),
                "label": rule.label or rule.title,
                "reason_code": rule.code,
                "severity": rule.severity,
                "category": rule.category,
            })

    if merge:
        highlights = _merge_overlapping(highlights, text)

    highlights.sort(key=lambda x: (-_severity_rank(x["severity"]), -x["score"], x["start"]))
    return highlights[:limit]


def detect_rule_reasons(text: str, limit: int = 6) -> List[Dict]:
    reasons: List[Dict] = []
    seen = set()

    for rule in RULES:
        if rule.code in seen:
            continue
        if rule.pattern.search(text):
            reasons.append({
                "code": rule.code,
                "title": rule.title,
                "description": rule.description,
                "category": rule.category,
                "severity": rule.severity,
                "weight": round(rule.weight, 4),
            })
            seen.add(rule.code)

    reasons.sort(key=lambda x: (-_severity_rank(x["severity"]), -x["weight"], x["title"]))
    return reasons[:limit]


def category_breakdown(text: str) -> Dict[str, float]:
    scores = {
        "phishing": 0.0,
        "scam": 0.0,
        "spam": 0.0,
        "social_engineering": 0.0,
        "financial": 0.0,
    }

    for rule in RULES:
        if rule.pattern.search(text):
            scores[rule.category] += rule.weight

    for key in scores:
        scores[key] = round(_clip_score(scores[key]), 4)

    return scores


def compute_rule_score(text: str) -> float:
    matched_weights = []
    matched_codes = set()

    for rule in RULES:
        if rule.code not in matched_codes and rule.pattern.search(text):
            matched_weights.append(rule.weight)
            matched_codes.add(rule.code)

    raw = sum(matched_weights)
    score = 1 - (1 / (1 + raw * 2.2))
    return round(_clip_score(score), 4)


def dominant_category(text: str) -> Optional[str]:
    breakdown = category_breakdown(text)
    best_cat = None
    best_score = 0.0

    for cat, score in breakdown.items():
        if score > best_score:
            best_cat = cat
            best_score = score

    return best_cat if best_score > 0 else None


def analyze_rules(text: str) -> Dict:
    highlights = detect_rule_highlights(text)
    reasons = detect_rule_reasons(text)
    breakdown = category_breakdown(text)
    rule_score = compute_rule_score(text)
    category = dominant_category(text)

    return {
        "rule_score": rule_score,
        "category_breakdown": breakdown,
        "dominant_category": category,
        "reasons": reasons,
        "highlights": highlights,
    }