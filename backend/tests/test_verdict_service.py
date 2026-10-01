from typing import Any

import pytest

from app.models.schemas import Recommendation, VerdictLabel
from app.services.verdict_service import (
    calculate_verdict,
    calculate_virustotal_verdict,
)


def make_record(
    *,
    malicious: int,
    suspicious: int,
    prevalence_score: int,
    signed: bool,
    first_seen_days_ago: int,
    source_conflicts: bool,
    telemetry_count: int,
) -> dict[str, Any]:
    return {
        "metadata": {
            "sha256": "f" * 64,
            "file_name": "sample.bin",
            "file_type": "binary",
            "file_size_bytes": 100,
            "first_seen_days_ago": first_seen_days_ago,
            "prevalence_score": prevalence_score,
            "signed": signed,
        },
        "detections": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": 10,
        },
        "signals": {
            "source_conflicts": source_conflicts,
            "telemetry_count": telemetry_count,
        },
    }


@pytest.mark.parametrize(
    "record,expected",
    [
        (
            make_record(
                malicious=15,
                suspicious=2,
                prevalence_score=10,
                signed=False,
                first_seen_days_ago=1,
                source_conflicts=False,
                telemetry_count=100,
            ),
            Recommendation.block,
        ),
        (
            make_record(
                malicious=0,
                suspicious=0,
                prevalence_score=90,
                signed=True,
                first_seen_days_ago=300,
                source_conflicts=False,
                telemetry_count=100,
            ),
            Recommendation.allow,
        ),
        (
            make_record(
                malicious=1,
                suspicious=7,
                prevalence_score=15,
                signed=False,
                first_seen_days_ago=2,
                source_conflicts=False,
                telemetry_count=50,
            ),
            Recommendation.detonate,
        ),
        (
            make_record(
                malicious=1,
                suspicious=4,
                prevalence_score=40,
                signed=True,
                first_seen_days_ago=20,
                source_conflicts=True,
                telemetry_count=70,
            ),
            Recommendation.rescan,
        ),
        (
            make_record(
                malicious=0,
                suspicious=0,
                prevalence_score=5,
                signed=False,
                first_seen_days_ago=2,
                source_conflicts=False,
                telemetry_count=2,
            ),
            Recommendation.human_review,
        ),
    ],
)
def test_calculate_verdict_all_recommendation_categories(
    record: dict[str, Any],
    expected: Recommendation,
) -> None:
    result = calculate_verdict(record)
    assert result.recommendation == expected
    assert result.rules_triggered


def test_virustotal_verdict_blocks_many_malicious_detections() -> None:
    result = calculate_virustotal_verdict(
        malicious=12, suspicious=0, analyzed_engines=70
    )
    assert result.verdict == VerdictLabel.malicious
    assert result.recommendation == Recommendation.block


def test_virustotal_zero_detections_remain_unknown() -> None:
    result = calculate_virustotal_verdict(
        malicious=0, suspicious=0, analyzed_engines=70
    )
    assert result.verdict == VerdictLabel.unknown
    assert result.recommendation == Recommendation.human_review
    assert "does not establish" in result.explanation
