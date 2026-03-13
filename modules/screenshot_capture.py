"""
EASM Scanner -- Screenshot Capture Module
Captures screenshots of web assets for visual fingerprinting.
Wraps gowitness (Go) or falls back to a headless-browser approach.
Stores screenshots in an output directory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ScreenshotResult:
    """Result of a screenshot capture."""
    url: str
    filepath: str = ""
    success: bool = False
    error: str = ""


class ScreenshotCapture:
    """Capture screenshots of web assets."""

    def __init__(
        self,
        output_dir: str = "screenshots",
        timeout: int = 30,
        verbose: bool = False,
    ) -> None:
        self.output_dir = output_dir
        self.timeout = timeout
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def capture(self, url: str) -> ScreenshotResult:
        """Capture a screenshot for a single URL."""
        result = ScreenshotResult(url=url)

        # Try gowitness
        gw = self._gowitness_single(url)
        if gw and gw.success:
            return gw

        # No headless browser fallback in Phase 2
        # (would need playwright/selenium -- deferred to Phase 4)
        result.error = (
            "gowitness not installed. "
            "Install: go install github.com/sensepost/gowitness@latest"
        )
        self._vprint(f"    [screenshot] {url}: {result.error}")
        return result

    def bulk_capture(self, urls: list[str]) -> list[ScreenshotResult]:
        """Capture screenshots for multiple URLs."""

        # Try gowitness bulk
        gw_results = self._gowitness_bulk(urls)
        if gw_results is not None:
            return gw_results

        # Fallback: individual captures
        results: list[ScreenshotResult] = []
        for url in urls:
            results.append(self.capture(url))

        captured = sum(1 for r in results if r.success)
        self._vprint(
            f"    [screenshot] captured {captured}/{len(urls)} screenshot(s)"
        )
        return results

    # ── gowitness wrapper ───────────────────────────────────

    def _gowitness_single(self, url: str) -> Optional[ScreenshotResult]:
        binary = shutil.which("gowitness")
        if not binary:
            return None

        result = ScreenshotResult(url=url)
        os.makedirs(self.output_dir, exist_ok=True)

        try:
            proc = subprocess.run(
                [
                    binary, "single", url,
                    "--screenshot-path", self.output_dir,
                    "--timeout", str(self.timeout),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout + 10,
            )
            # gowitness saves as URL-encoded filename
            # Check if a screenshot was created
            screenshots = list(Path(self.output_dir).glob("*.png"))
            if screenshots:
                latest = max(screenshots, key=lambda p: p.stat().st_mtime)
                result.filepath = str(latest)
                result.success = True
                self._vprint(
                    f"    [gowitness] {url}: saved -> {result.filepath}"
                )
            else:
                result.error = "No screenshot file generated"

        except subprocess.TimeoutExpired:
            result.error = "Timeout"
        except Exception as exc:
            result.error = str(exc)

        return result

    def _gowitness_bulk(
        self, urls: list[str],
    ) -> Optional[list[ScreenshotResult]]:
        binary = shutil.which("gowitness")
        if not binary:
            return None

        os.makedirs(self.output_dir, exist_ok=True)

        # Write URLs to temp file
        url_file = os.path.join(self.output_dir, "_urls.txt")
        with open(url_file, "w") as f:
            f.write("\n".join(urls))

        results: list[ScreenshotResult] = []
        try:
            # Count existing screenshots before
            existing = set(Path(self.output_dir).glob("*.png"))

            proc = subprocess.run(
                [
                    binary, "file",
                    "--file", url_file,
                    "--screenshot-path", self.output_dir,
                    "--timeout", str(self.timeout),
                    "--threads", "4",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout * len(urls) + 60,
            )

            # Count new screenshots
            all_screenshots = set(Path(self.output_dir).glob("*.png"))
            new_screenshots = all_screenshots - existing

            self._vprint(
                f"    [gowitness] captured {len(new_screenshots)} "
                f"screenshot(s)"
            )

            # Map URLs to results
            for url in urls:
                results.append(ScreenshotResult(
                    url=url,
                    success=True,  # approximate
                    filepath=self.output_dir,
                ))

        except subprocess.TimeoutExpired:
            self._vprint("    [gowitness] bulk timeout")
            return None
        except Exception as exc:
            self._vprint(f"    [gowitness] bulk error: {exc}")
            return None
        finally:
            # Clean up temp file
            try:
                os.remove(url_file)
            except OSError:
                pass

        return results

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
