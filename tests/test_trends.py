"""Tests for risk trend-over-time (pure compute + scheduler loader). No network."""
from modules.trends import (
    compute_trends,
    render_console,
    _sparkline,
    _SPARK,
    LOWER_IS_BETTER,
)
from modules.scheduler import ScanScheduler


# ── compute_trends ──────────────────────────────────────────────────

def test_empty_and_single_point():
    assert compute_trends([]).points == 0
    assert "No scan history" in render_console(compute_trends([]))
    one = compute_trends([{"scan_time": "t0", "total_findings": 5,
                           "critical": 1, "high": 1}])
    assert one.points == 1
    assert "Only one scan" in render_console(one)


def _series():
    return [
        {"scan_time": "2026-01-01", "total_assets": 40, "total_findings": 100,
         "critical": 10, "high": 20, "medium": 30, "low": 40},
        {"scan_time": "2026-02-01", "total_assets": 42, "total_findings": 70,
         "critical": 6, "high": 14, "medium": 25, "low": 25},
        {"scan_time": "2026-03-01", "total_assets": 45, "total_findings": 50,
         "critical": 2, "high": 8, "medium": 20, "low": 20},
    ]


def test_improving_trend_and_exposure_reduction():
    r = compute_trends(_series())
    assert r.points == 3
    tf = r.metrics["total_findings"]
    assert tf.first == 100 and tf.last == 50
    assert tf.delta == -50 and tf.pct_change == -50.0
    assert tf.direction == "improving"
    # exposure (crit+high): 30 -> 10  => 66.7% reduction
    assert r.exposure_reduction_pct == 66.7


def test_worsening_and_stable_direction():
    worse = compute_trends([
        {"scan_time": "a", "total_findings": 10, "critical": 1, "high": 1},
        {"scan_time": "b", "total_findings": 20, "critical": 3, "high": 3},
    ])
    assert worse.metrics["total_findings"].direction == "worsening"
    assert worse.metrics["total_findings"].pct_change == 100.0
    assert worse.exposure_reduction_pct == -200.0   # exposure (2 -> 6) grew

    flat = compute_trends([
        {"scan_time": "a", "total_findings": 10, "critical": 1, "high": 1},
        {"scan_time": "b", "total_findings": 10, "critical": 1, "high": 1},
    ])
    assert flat.metrics["total_findings"].direction == "stable"


def test_total_assets_is_not_scored_as_good_or_bad():
    r = compute_trends(_series())
    assert "total_assets" not in LOWER_IS_BETTER
    assert r.metrics["total_assets"].direction == "n/a"


def test_metric_selection_and_absent_metrics_skipped():
    pts = [{"scan_time": "a", "critical": 5}, {"scan_time": "b", "critical": 2}]
    r = compute_trends(pts, metrics=("critical", "risk_avg"))
    assert "critical" in r.metrics
    assert "risk_avg" not in r.metrics              # absent from the data


def test_sparkline_is_ascii_and_right_length():
    spark = _sparkline([1, 5, 2, 8, 3])
    assert len(spark) == 5
    assert all(ch in _SPARK for ch in spark)
    assert _sparkline([]) == ""


def test_render_console_ascii_only():
    out = render_console(compute_trends(_series()))
    assert "total_findings" in out and "exposure" in out
    assert out.isascii()


# ── scheduler.trend_points loader ───────────────────────────────────

def test_scheduler_trend_points_parses_history(tmp_path):
    db = str(tmp_path / "hist.db")
    sched = ScanScheduler(db_path=db)

    def summary(c, h, m, low, avg, mx):
        return {"findings": {"CRITICAL": c, "HIGH": h, "MEDIUM": m, "LOW": low},
                "risk": {"avg_score": avg, "max_score": mx}}

    sched.record_scan("cli", findings=[{"rule_id": "r1", "severity": "CRITICAL",
                                        "asset_value": "a"}],
                      assets=[{"asset_type": "domain", "value": "a.com"}],
                      summary=summary(1, 2, 3, 4, 55.0, 90.0), duration=1.0)
    sched.record_scan("cli", findings=[],
                      assets=[{"asset_type": "domain", "value": "a.com"}],
                      summary=summary(0, 1, 2, 2, 30.0, 60.0), duration=1.0)

    points = sched.trend_points("cli")
    assert len(points) == 2
    # chronological: first recorded has more exposure than second
    assert points[0]["critical"] == 1 and points[1]["critical"] == 0
    assert points[0]["medium"] == 3 and points[1]["low"] == 2
    assert points[0]["risk_avg"] == 55.0 and points[1]["risk_max"] == 60.0

    # end-to-end: trend over the two recorded scans shows reduced exposure
    report = compute_trends(points)
    assert report.points == 2
    assert report.exposure_reduction_pct > 0        # (1+2)=3 -> (0+1)=1
