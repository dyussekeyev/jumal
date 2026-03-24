import subprocess
import tempfile
import shutil
import os
import json
import logging
from typing import Optional, Dict, Any


DOCKER_IMAGE = "jumal-analyzer:latest"
DEFAULT_TIMEOUT = 300  # 5 minutes overall container timeout


class DockerRunnerError(Exception):
    pass


class DockerRunner:
    """
    Runs static analysis inside a Docker container.

    The container receives:
      - the sample as /workspace/input/sample (read-only bind mount)
      - a writable output dir at /workspace/output

    It produces /workspace/output/result.json which is read and returned.
    """

    def __init__(
        self,
        image: str = DOCKER_IMAGE,
        dockerfile_path: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        yara_rules_dir: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.image = image
        self.dockerfile_path = dockerfile_path or self._default_dockerfile_path()
        self.timeout = timeout
        self.yara_rules_dir = yara_rules_dir
        self.logger = logger or logging.getLogger(__name__)

    def _default_dockerfile_path(self) -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(here, "..", "..", "docker", "analyzer")

    def is_docker_available(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def image_exists(self) -> bool:
        """Check if the analyzer image already exists locally."""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self.image],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def build_image(self) -> bool:
        """Build the analyzer Docker image from the bundled Dockerfile."""
        self.logger.info(f"Building Docker image: {self.image} from {self.dockerfile_path}")
        try:
            result = subprocess.run(
                ["docker", "build", "-t", self.image, self.dockerfile_path],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode != 0:
                self.logger.error(f"Docker build failed: {result.stderr}")
                return False
            self.logger.info("Docker image built successfully")
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.error(f"Docker build error: {e}")
            return False

    def _empty_result(self, error_msg: str) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "errors": [error_msg],
            "tool_runs": [],
            "sample": {},
            "file_type": {},
            "generic_analysis": {},
            "specialized_analysis": {},
            "risk_hints": [],
        }

    def run_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Run static analysis on *file_path* inside the Docker container.

        Returns a dict matching the schema produced by analyzer_entry.py.
        Never raises – errors are captured inside the returned dict.
        """
        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            return self._empty_result(f"File not found: {file_path}")

        # Ensure image exists; auto-build on first use
        if not self.image_exists():
            self.logger.info(
                "[*] Image '%s' not found locally – building automatically "
                "(this may take several minutes)...",
                self.image,
            )
            if not self.build_image():
                return self._empty_result(
                    f"Failed to auto-build image '{self.image}'. "
                    "Manual fallback: docker build -t jumal-analyzer:latest docker/analyzer"
                )
            self.logger.info("[*] Image '%s' built successfully", self.image)

        output_dir = tempfile.mkdtemp(prefix="jumal_output_")
        try:
            file_name = os.path.basename(file_path)

            cmd = [
                "docker", "run", "--rm",
                "--network=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--tmpfs=/tmp:rw,noexec,nosuid,size=256m",
                "-v", f"{file_path}:/workspace/input/sample:ro",
                "-v", f"{output_dir}:/workspace/output:rw",
                "-e", f"SAMPLE_NAME={file_name}",
            ]

            if self.yara_rules_dir and os.path.isdir(self.yara_rules_dir):
                cmd += ["-v", f"{self.yara_rules_dir}:/workspace/rules:ro"]

            cmd.append(self.image)

            self.logger.info(f"Running Docker container for: {file_name}")
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
            except subprocess.TimeoutExpired:
                self.logger.error(f"Container timed out after {self.timeout}s")
                return self._empty_result(f"Container timed out after {self.timeout}s")

            if proc.returncode != 0:
                self.logger.warning(
                    f"Container exited with code {proc.returncode}: {proc.stderr[:300]}"
                )

            result_path = os.path.join(output_dir, "result.json")
            if os.path.isfile(result_path):
                with open(result_path, "r", encoding="utf-8") as f:
                    return json.load(f)

            self.logger.error("No result.json produced by container")
            return self._empty_result(
                f"Container produced no result. Exit={proc.returncode}. "
                f"Stderr: {proc.stderr[:300]}"
            )

        except Exception as e:
            self.logger.exception("Unexpected error in DockerRunner.run_analysis")
            return self._empty_result(f"Unexpected error: {e}")
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)
