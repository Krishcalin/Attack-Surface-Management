"""
EASM Scanner -- Risk Trend-Over-Time
====================================
Turns the scan history (recorded by the scheduler) into trend metrics so teams
can see whether their attack surface is shrinking over time -- the "footprint
reduction" view that ASI platforms surface (cf. Recorded Future's "51% reduction
in vulnerable attack surface").

Pure and offline: ``compute_trends`` operates on a chronological list of metric
points (plain dicts); a thin loader pulls those points from the scheduler DB.
ASCII-only console rendering (Windows-safe).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# Metrics where a DECREASE is an improvement (security got better).
LOWER_IS_BETTER: frozenset = frozenset({
    "total_findings", "critical", "high", "medium", "low",
    "risk_avg", "risk_max", "exposure",
})

# Default metrics to trend, in display order.
DEFAULT_METRICS: tuple = (
    "total_assets", "total_findings", "critical", "high",
    "medium", "low", "risk_avg", "risk_max",
)

_SPARK = " .:-=+*#"   # ASCII ramp, low -> high


@dataclass
class MetricTrend:
    name: str
    series: list[float] = field(default_factory=list)
    first: float = 0.0
    last: float = 0.0
    delta: float = 0.0           # last - first
    pct_change: float = 0.0      # signed % vs first
    direction: str = "n/a"       # improving | worsening | stable | n/a
    spark: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrendReport:
    points: int = 0
    span: str = ""
    metrics: dict[str, MetricTrend] = field(default_factory=dict)
    exposure_reduction_pct: float = 0.0   # reduction in (critical+high); +=better

    def to_dict(self) -> dict[str, Any]:
        return {
            "points": self.points,
            "span": self.span,
            "exposure_reduction_pct": self.exposure_reduction_pct,
            "metrics": {k: v.to_dict() for k, v in self.metrics.items()},
        }


def _sparkline(series: list[float]) -> str:
    vals = [float(v) for v in series]
    if not vals:
        return ""
    lo, hi = min(vals), max(vals)
    if hi == lo:
        return _SPARK[1] * len(vals)
    out = []
    for v in vals:
        idx = int((v - lo) / (hi - lo) * (len(_SPARK) - 1))
        out.append(_SPARK[idx])
    return "".join(out)


def _direction(name: str, first: float, last: float) -> str:
    if name not in LOWER_IS_BETTER:
        return "n/a"
    if last < first:
        return "improving"
    if last > first:
        return "worsening"
    return "stable"


def compute_trends(
    points: list[dict],
    metrics: Optional[tuple] = None,
) -> TrendReport:
    """Compute trends from a chronological list of metric points.

    Each point is a dict that may contain any of the DEFAULT_METRICS keys plus
    a ``scan_time``. Points must be ordered oldest -> newest.
    """
    metrics = metrics or DEFAULT_METRICS
    report = TrendReport(points=len(points))
    if not points:
        return report

    times = [p.get("scan_time", "") for p in points]
    report.span = f"{times[0]} .. {times[-1]}" if times[0] or times[-1] else ""

    for name in metrics:
        if all(name not in p for p in points):
            continue                                 # metric absent -> skip
        series = [float(p.get(name, 0) or 0) for p in points]
        first, last = series[0], series[-1]
        report.metrics[name] = MetricTrend(
            name=name,
            series=series,
            first=first,
            last=last,
            delta=round(last - first, 2),
            pct_change=round((last - first) / first * 100, 1) if first else 0.0,
            direction=_direction(name, first, last),
            spark=_sparkline(series),
        )

    # Attack-surface exposure = CRITICAL + HIGH; reduction is positive when good.
    exp = [float(p.get("critical", 0) or 0) + float(p.get("high", 0) or 0)
           for p in points]
    if exp and exp[0] > 0:
        report.exposure_reduction_pct = round((exp[0] - exp[-1]) / exp[0] * 100, 1)
    return report


def render_console(report: TrendReport) -> str:
    """ASCII trend report for the console (Windows-safe)."""
    if report.points == 0:
        return "  No scan history yet -- run more scans to see trends."
    if report.points == 1:
        return ("  Only one scan recorded -- trends appear after the second "
                "scan.")
    lines = [
        f"  Scans: {report.points}    Span: {report.span}",
        f"  Attack-surface exposure (CRITICAL+HIGH) change: "
        f"{_signed(report.exposure_reduction_pct)}% "
        f"({'reduced' if report.exposure_reduction_pct > 0 else 'increased' if report.exposure_reduction_pct < 0 else 'unchanged'})",
        "",
        f"  {'metric':<16}{'first':>8}{'last':>8}{'change':>10}  trend",
        f"  {'-' * 54}",
    ]
    arrow = {"improving": "v better", "worsening": "^ worse",
             "stable": "= flat", "n/a": ""}
    for name, m in report.metrics.items():
        change = f"{_signed(m.pct_change)}%"
        lines.append(
            f"  {name:<16}{m.first:>8.0f}{m.last:>8.0f}{change:>10}  "
            f"{m.spark}  {arrow.get(m.direction, '')}"
        )
    return "\n".join(lines)


def _signed(v: float) -> str:
    return f"+{v}" if v > 0 else f"{v}"
