from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum


class VTFileStatus(Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"


@dataclass
class ToolRun:
    tool: str
    status: str  # ok | error | timeout | not_found | skipped
    duration_ms: int = 0
    stderr: str = ""
    error: str = ""


@dataclass
class StaticAnalysisResult:
    schema_version: str = "1.0"
    sample: Dict[str, Any] = field(default_factory=dict)
    file_type: Dict[str, Any] = field(default_factory=dict)
    generic_analysis: Dict[str, Any] = field(default_factory=dict)
    specialized_analysis: Dict[str, Any] = field(default_factory=dict)
    tool_runs: List[ToolRun] = field(default_factory=list)
    risk_hints: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class FileAnalysisPipelineResult:
    file_path: str
    local_static: Optional[StaticAnalysisResult] = None
    vt_status: VTFileStatus = VTFileStatus.SKIPPED
    vt_aggregated: Optional[Dict[str, Any]] = None
    vt_raw: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    pipeline_errors: List[str] = field(default_factory=list)
