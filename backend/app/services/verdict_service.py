from typing import Any

from app.models.schemas import Recommendation, VerdictLabel, VerdictResult


def calculate_verdict(record: dict[str, Any]) -> VerdictResult:
    """Return an explainable verdict from synthetic reputation signals."""
    metadata = record["metadata"]
    detections = record["detections"]
    signals = record["signals"]

    malicious = detections["malicious"]
    suspicious = detections["suspicious"]
    prevalence_score = metadata["prevalence_score"]
    signed = metadata["signed"]
    first_seen_days_ago = metadata["first_seen_days_ago"]
    source_conflicts = signals["source_conflicts"]
    telemetry_count = signals["telemetry_count"]

    risk_score = 10
    rules_triggered: list[str] = []

    if malicious >= 10:
        risk_score += 70
        rules_triggered.append("High malicious detection count (>=10).")
    elif malicious >= 3:
        risk_score += 45
        rules_triggered.append("Moderate malicious detections (3-9).")
    elif malicious > 0:
        risk_score += 25
        rules_triggered.append("Low but non-zero malicious detections (1-2).")

    if suspicious >= 5:
        risk_score += 20
        rules_triggered.append("Elevated suspicious detections (>=5).")
    elif suspicious > 0:
        risk_score += 10
        rules_triggered.append("Some suspicious detections present.")

    if not signed:
        risk_score += 10
        rules_triggered.append("Unsigned file.")

    if first_seen_days_ago <= 7:
        risk_score += 10
        rules_triggered.append("Very recent first-seen timestamp (<=7 days).")

    if prevalence_score < 20:
        risk_score += 10
        rules_triggered.append("Low prevalence score (<20).")

    if source_conflicts:
        risk_score += 15
        rules_triggered.append("Conflicting reputation source signals.")

    risk_score = min(risk_score, 100)

    if malicious >= 10:
        return VerdictResult(
            verdict=VerdictLabel.malicious,
            recommendation=Recommendation.block,
            confidence="high",
            risk_score=risk_score,
            rules_triggered=rules_triggered,
            explanation="Strong malicious detections indicate high confidence risk.",
        )

    if source_conflicts:
        return VerdictResult(
            verdict=VerdictLabel.mixed,
            recommendation=Recommendation.rescan,
            confidence="medium",
            risk_score=risk_score,
            rules_triggered=rules_triggered,
            explanation=(
                "Signals disagree across sources, so the sample should be rescanned"
                " before making a final allow or block decision."
            ),
        )

    if telemetry_count < 5 and malicious == 0 and suspicious == 0:
        rules_triggered.append("Insufficient telemetry volume (<5 observations).")
        return VerdictResult(
            verdict=VerdictLabel.unknown,
            recommendation=Recommendation.human_review,
            confidence="low",
            risk_score=max(risk_score, 35),
            rules_triggered=rules_triggered,
            explanation=(
                "There is not enough evidence to classify this sample with confidence,"
                " so conservative human review is recommended."
            ),
        )

    if risk_score >= 60:
        return VerdictResult(
            verdict=VerdictLabel.suspicious,
            recommendation=Recommendation.detonate,
            confidence="medium",
            risk_score=risk_score,
            rules_triggered=rules_triggered,
            explanation="Risk is elevated but not definitive, so detonation is recommended.",
        )

    if (
        malicious == 0
        and suspicious == 0
        and prevalence_score >= 70
        and signed
        and first_seen_days_ago >= 30
        and telemetry_count >= 20
    ):
        rules_triggered.append("No detections with strong historical prevalence and signature.")
        return VerdictResult(
            verdict=VerdictLabel.likely_clean,
            recommendation=Recommendation.allow,
            confidence="medium",
            risk_score=risk_score,
            rules_triggered=rules_triggered,
            explanation=(
                "Current signals suggest low risk, but the result remains a reputation"
                " assessment rather than proof of safety."
            ),
        )

    rules_triggered.append("Evidence is partial or ambiguous for a final verdict.")
    return VerdictResult(
        verdict=VerdictLabel.unknown,
        recommendation=Recommendation.human_review,
        confidence="low",
        risk_score=max(risk_score, 40),
        rules_triggered=rules_triggered,
        explanation="The safest action is conservative review due to ambiguous evidence.",
    )


def calculate_virustotal_verdict(
    *, malicious: int, suspicious: int, analyzed_engines: int
) -> VerdictResult:
    """Return a conservative verdict based only on VirusTotal analysis counts."""
    rules_triggered = [f"VirusTotal analyzed {analyzed_engines} engines."]

    if malicious >= 10:
        rules_triggered.append("High malicious detection count (>=10).")
        return VerdictResult(
            verdict=VerdictLabel.malicious,
            recommendation=Recommendation.block,
            confidence="high",
            risk_score=95,
            rules_triggered=rules_triggered,
            explanation="Many VirusTotal engines identify this file as malicious.",
        )

    if malicious > 0 or suspicious > 0:
        rules_triggered.append(
            "VirusTotal reported malicious or suspicious detections."
        )
        return VerdictResult(
            verdict=VerdictLabel.suspicious,
            recommendation=Recommendation.detonate,
            confidence="medium",
            risk_score=min(90, 50 + malicious * 3 + suspicious * 2),
            rules_triggered=rules_triggered,
            explanation=(
                "VirusTotal reports detections that warrant further analysis before"
                " allowing this file."
            ),
        )

    rules_triggered.append("No malicious or suspicious detections were reported.")
    return VerdictResult(
        verdict=VerdictLabel.unknown,
        recommendation=Recommendation.human_review,
        confidence="low",
        risk_score=35,
        rules_triggered=rules_triggered,
        explanation=(
            "No detections were reported, but this alone does not establish that the"
            " file is safe. Use additional evidence and review before allowing it."
        ),
    )
