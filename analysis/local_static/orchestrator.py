import os
import hashlib
import logging
from typing import Optional, Dict, Any, Callable, Tuple

from .models import (
    FileAnalysisPipelineResult,
    StaticAnalysisResult,
    ToolRun,
    VTFileStatus,
)
from .docker_runner import DockerRunner

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


class FileAnalysisOrchestrator:
    """
    Orchestrates the local file analysis pipeline:
      1. Docker static analysis (container computes hashes internally)
      2. Extract hashes from Docker container result
      3. VT hash-only lookup (never uploads) — only if use_vt is True
      4. Return FileAnalysisPipelineResult
    """

    def __init__(
        self,
        vt_client=None,
        docker_runner: Optional[DockerRunner] = None,
        logger: Optional[logging.Logger] = None,
        max_file_size: int = MAX_FILE_SIZE,
        progress_callback: Optional[Callable[[str], None]] = None,
        use_vt: bool = True,
    ):
        self.vt_client = vt_client
        self.docker_runner = docker_runner if docker_runner is not None else DockerRunner(logger=logger)
        self.logger = logger or logging.getLogger(__name__)
        self.max_file_size = max_file_size
        self.progress_callback = progress_callback or (lambda msg: None)
        self.use_vt = use_vt

    def _progress(self, msg: str) -> None:
        self.logger.info(msg)
        self.progress_callback(msg)

    def _compute_hashes(self, file_path: str) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    def _vt_lookup(
        self, sha256: str
    ) -> Tuple[VTFileStatus, Optional[Dict[str, Any]]]:
        """Query VT by hash only.  Never submits/uploads the file."""
        if not self.vt_client:
            self.logger.info("No VT client configured – skipping VT lookup")
            return VTFileStatus.SKIPPED, None

        try:
            self._progress("[*] Querying VirusTotal by hash (no upload)...")
            file_report = self.vt_client.get_file_report(sha256)

            if file_report.get("ok") is False:
                status_code = file_report.get("status", 0)
                if status_code == 404:
                    self._progress("[*] File not found in VirusTotal")
                    return VTFileStatus.NOT_FOUND, None
                if status_code == 429:
                    self._progress("[!] VirusTotal rate limit reached")
                    return VTFileStatus.RATE_LIMITED, None
                self._progress(f"[!] VirusTotal error (status {status_code})")
                return VTFileStatus.ERROR, None

            vt_data: Dict[str, Any] = {"file_report": file_report}

            # Collect optional endpoints – failures are non-fatal
            for key, method_name in [
                ("behaviour", "get_behaviour"),
                ("behaviour_mitre_trees", "get_behaviour_mitre_trees"),
                ("comments", "get_comments"),
            ]:
                try:
                    method = getattr(self.vt_client, method_name)
                    vt_data[key] = (
                        method(sha256, limit=20)
                        if key == "comments"
                        else method(sha256)
                    )
                except Exception as e:
                    self.logger.warning(f"VT optional endpoint {method_name}: {e}")
                    vt_data[key] = {"ok": False, "error": str(e)}

            return VTFileStatus.OK, vt_data

        except Exception as e:
            self.logger.exception("VT lookup failed")
            self._progress(f"[!] VirusTotal lookup error: {e}")
            return VTFileStatus.ERROR, None

    def _parse_static_result(self, raw: Dict[str, Any]) -> StaticAnalysisResult:
        tool_runs = [
            ToolRun(
                tool=tr.get("tool", "unknown"),
                status=tr.get("status", "unknown"),
                duration_ms=tr.get("duration_ms", 0),
                stderr=tr.get("stderr", ""),
                error=tr.get("error", ""),
            )
            for tr in raw.get("tool_runs", [])
            if isinstance(tr, dict)
        ]
        return StaticAnalysisResult(
            schema_version=raw.get("schema_version", "1.0"),
            sample=raw.get("sample", {}),
            file_type=raw.get("file_type", {}),
            generic_analysis=raw.get("generic_analysis", {}),
            specialized_analysis=raw.get("specialized_analysis", {}),
            tool_runs=tool_runs,
            risk_hints=raw.get("risk_hints", []),
            errors=raw.get("errors", []),
        )

    def run(self, file_path: str) -> FileAnalysisPipelineResult:
        """
        Run the full analysis pipeline for *file_path*.

        Always returns a result – partial results are returned on tool failures.
        """
        result = FileAnalysisPipelineResult(file_path=file_path)

        # --- Validate ---
        if not os.path.isfile(file_path):
            result.pipeline_errors.append(f"File not found: {file_path}")
            return result

        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            result.pipeline_errors.append(
                f"File too large: {file_size} bytes (max {self.max_file_size})"
            )
            return result

        # --- Step 1: Docker static analysis (container computes hashes internally) ---
        hashes = None
        if self.docker_runner.is_docker_available():
            self._progress("[*] Starting Docker static analysis...")
            try:
                raw_static = self.docker_runner.run_analysis(file_path)
                static_result = self._parse_static_result(raw_static)

                # Extract hashes from container result
                hashes = static_result.sample.get("hashes") if static_result.sample else None

                # Fill in file metadata where container couldn't provide it
                merged_sample = dict(static_result.sample) if static_result.sample else {}
                if not merged_sample.get("file_name"):
                    merged_sample["file_name"] = os.path.basename(file_path)
                if not merged_sample.get("file_size"):
                    merged_sample["file_size"] = file_size
                static_result.sample = merged_sample

                result.local_static = static_result
                self._progress("[*] Docker static analysis complete")
            except Exception as e:
                result.pipeline_errors.append(f"Docker analysis failed: {e}")
                self.logger.exception("Docker analysis failed")
        else:
            self._progress("[!] Docker not available – static analysis skipped")
            result.pipeline_errors.append(
                "Docker not available – static analysis skipped"
            )

        # --- Step 2: Extract hashes — fall back to host computation if Docker didn't provide them ---
        if not hashes:
            self._progress("[*] Computing file hashes (MD5/SHA1/SHA256)...")
            try:
                hashes = self._compute_hashes(file_path)
                self.logger.info(f"SHA256: {hashes['sha256']}")
            except Exception as e:
                result.pipeline_errors.append(f"Hash computation failed: {e}")
                self.logger.exception("Hash computation failed")
                return result

            # Back-fill hashes into the static result (Docker was unavailable)
            if result.local_static is None:
                result.local_static = StaticAnalysisResult(
                    sample={
                        "file_name": os.path.basename(file_path),
                        "file_size": file_size,
                        "hashes": hashes,
                    }
                )
            elif not result.local_static.sample.get("hashes"):
                merged = dict(result.local_static.sample)
                merged["hashes"] = hashes
                result.local_static.sample = merged
        else:
            self.logger.info(f"SHA256: {hashes.get('sha256', 'unknown')}")

        result.hashes = hashes

        # --- Step 3: VT lookup (hash-only) — only if use_vt is enabled ---
        if self.use_vt:
            sha256 = hashes.get("sha256", "")
            if sha256:
                vt_status, vt_raw = self._vt_lookup(sha256)
                result.vt_status = vt_status
                result.vt_raw = vt_raw
            else:
                self.logger.warning("SHA256 hash unavailable – skipping VT lookup")

        return result
