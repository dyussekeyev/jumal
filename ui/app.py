import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import json
import os
from typing import Dict, Any, Optional
from core.hashutil import detect_hash_type
from clients.vt_client import VTClient, VTAuthError
from clients.llm_client import (
    LLMClient,
    LLMAuthError,
    LLMBadRequestError,
    LLMServerError,
    LLMClientError
)
from core.aggregator import Aggregator
from core.summarizer import Summarizer
from core.ioc_extractor import IOCExtractor
from analysis.local_static.orchestrator import FileAnalysisOrchestrator
from analysis.local_static.context_builder import CombinedContextBuilder

# Optional VT enrichment endpoints we query (all treated as non-fatal if forbidden):
#   behaviour              -> sandbox behaviour reports
#   behaviour_mitre_trees  -> MITRE ATT&CK summary
#   comments               -> latest comments
OPTIONAL_ENDPOINTS = [
    ("behaviour", "msg_fetch_behaviour", "get_behaviour"),
    ("behaviour_mitre_trees", "msg_fetch_mitre", "get_behaviour_mitre_trees"),
    ("comments", "msg_fetch_comments", "get_comments")
]


class JUMALApp:
    def __init__(self, config_manager, logger):
        self.cfg_manager = config_manager
        self.config = config_manager.get()
        self.logger = logger
        self.root = tk.Tk()
        self.root.title("JUMAL - Junior Malware Analyst")
        self.root.geometry("1000x700")

        self.lang_data = {}
        self.current_lang = self.config.get("ui", {}).get("default_language", "en")
        self._load_languages()
        self._init_ui()

        self.vt_client = None
        self.llm_client = None
        self.aggregator = Aggregator(self.logger)
        self.summarizer = Summarizer(self.logger, self.config)
        self.ioc_extractor = IOCExtractor(self.logger, self.config)
        self._init_clients()

        self._progress_stage = tk.StringVar(value="Idle")
        self._status_message(self._t("status_idle"))

        # Analysis lock to prevent concurrent/duplicate analysis runs
        self._analysis_running = False

        # Stored data for report saving
        self._last_aggregated = None
        self._last_vt_data = None
        self._last_ioc_summary = None
        self._last_ioc_result = None
        self._last_file_pipeline_result = None
        self._last_file_analysis_text = ""

    # ------------- Internationalization -------------
    def _load_languages(self):
        lang_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "i18n")
        for fname in ("en.json", "ru.json", "kz.json"):
            path = os.path.join(lang_dir, fname)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    try:
                        self.lang_data[fname[:2]] = json.load(f)
                    except Exception:
                        self.lang_data[fname[:2]] = {}
        if self.current_lang not in self.lang_data:
            self.current_lang = "en"

    def _t(self, key: str):
        return self.lang_data.get(self.current_lang, {}).get(key, key)

    # ------------- Clients -------------
    def _init_clients(self):
        vt_cfg = self.config.get("virustotal", {})
        net_cfg = self.config.get("network", {})
        self.vt_client = VTClient(
            api_key=vt_cfg.get("api_key", ""),
            base_url=vt_cfg.get("base_url", "https://www.virustotal.com/api/v3"),
            min_interval=vt_cfg.get("min_interval_seconds", 15),
            max_retries=vt_cfg.get("max_retries", 3),
            backoff_base=vt_cfg.get("retry_backoff_base", 5),
            timeout=net_cfg.get("request_timeout_seconds", 30),
            user_agent=net_cfg.get("user_agent", "JUMAL/0.1"),
            logger=self.logger
        )
        llm_cfg = self.config.get("llm", {})
        self.llm_client = LLMClient(
            base_url=llm_cfg.get("provider_url", "https://openrouter.ai/api/v1"),
            api_key=llm_cfg.get("api_key", ""),
            model=llm_cfg.get("model", "meta-llama/llama-3.2-1b-instruct"),
            stream_enabled=llm_cfg.get("stream_enabled", True),
            timeout=net_cfg.get("request_timeout_seconds", 30),
            logger=self.logger
        )

    # ------------- UI Construction -------------
    def _init_ui(self):
        self.notebook = ttk.Notebook(self.root)

        # Create tab frames in the desired display order:
        # 1. File Analysis  2. VT-only Analysis  3. Indicators/Rules  4. Raw
        self.frame_file_analysis = ttk.Frame(self.notebook)
        self.frame_vt_analysis = ttk.Frame(self.notebook)
        self.frame_indicators = ttk.Frame(self.notebook)
        self.frame_raw = ttk.Frame(self.notebook)

        self.notebook.add(self.frame_file_analysis, text=self._t("tab_file_analysis"))
        self.notebook.add(self.frame_vt_analysis, text=self._t("tab_vt_analysis"))
        self.notebook.add(self.frame_indicators, text=self._t("tab_indicators"))
        self.notebook.add(self.frame_raw, text=self._t("tab_raw"))

        # Build each tab's contents
        self._build_file_analysis_tab()
        self._build_vt_analysis_tab()

        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Indicators tab
        indicators_top = ttk.Frame(self.frame_indicators)
        indicators_top.pack(fill=tk.X, pady=5, padx=5)
        ttk.Button(indicators_top, text=self._t("btn_copy_indicators"),
                   command=self._on_copy_indicators).pack(side=tk.LEFT)

        self.text_indicators = scrolledtext.ScrolledText(
            self.frame_indicators, wrap=tk.WORD, state=tk.DISABLED
        )
        self.text_indicators.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Raw tab
        raw_top = ttk.Frame(self.frame_raw)
        raw_top.pack(fill=tk.X, pady=5, padx=5)
        ttk.Button(raw_top, text=self._t("btn_copy_raw"),
                   command=self._on_copy_raw).pack(side=tk.LEFT)

        self.text_raw = scrolledtext.ScrolledText(
            self.frame_raw, wrap=tk.WORD, state=tk.DISABLED
        )
        self.text_raw.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status bar
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_label = ttk.Label(status_frame, text="")
        self.status_label.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress.pack(side=tk.RIGHT, padx=5)

    def _build_vt_analysis_tab(self):
        """Build the VT-only Analysis tab: hash input, action buttons, and result text area."""
        top_frame = ttk.Frame(self.frame_vt_analysis)
        top_frame.pack(fill=tk.X, pady=5, padx=5)

        ttk.Label(top_frame, text=self._t("label_hash")).pack(side=tk.LEFT)
        self.entry_hash = ttk.Entry(top_frame, width=60)
        self.entry_hash.pack(side=tk.LEFT, padx=5)

        # Hash clipboard actions
        ttk.Button(top_frame, text=self._t("btn_clear"),
                   command=self._on_clear_hash, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text=self._t("btn_copy"),
                   command=self._on_copy_hash, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text=self._t("btn_paste"),
                   command=self._on_paste_hash, width=6).pack(side=tk.LEFT, padx=2)

        ttk.Button(top_frame, text=self._t("btn_get_report"),
                   command=self._on_get_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text=self._t("btn_copy_summary"),
                   command=self._on_copy_vt_summary).pack(side=tk.LEFT)
        ttk.Button(top_frame, text=self._t("btn_save_report"),
                   command=self._on_save_vt_report).pack(side=tk.LEFT, padx=5)

        self.text_vt_analysis = scrolledtext.ScrolledText(
            self.frame_vt_analysis, wrap=tk.WORD, state=tk.DISABLED
        )
        self.text_vt_analysis.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _build_file_analysis_tab(self):
        """Build the File Analysis tab: path input, action buttons, and result text area."""
        top_frame = ttk.Frame(self.frame_file_analysis)
        top_frame.pack(fill=tk.X, pady=5, padx=5)

        ttk.Label(top_frame, text=self._t("label_file_path")).pack(side=tk.LEFT)
        self.entry_file_path = ttk.Entry(top_frame, width=55)
        self.entry_file_path.pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text=self._t("btn_browse"),
                   command=self._on_browse_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text=self._t("btn_analyze_file"),
                   command=self._on_analyze_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text=self._t("btn_copy_summary"),
                   command=self._on_copy_file_summary).pack(side=tk.LEFT)
        ttk.Button(top_frame, text=self._t("btn_save_report"),
                   command=self._on_save_file_report).pack(side=tk.LEFT, padx=5)

        self.text_file_analysis = scrolledtext.ScrolledText(
            self.frame_file_analysis, wrap=tk.WORD, state=tk.DISABLED
        )
        self.text_file_analysis.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # ------------- Helpers -------------
    def _status_message(self, msg: str):
        """Display a status message in the status bar."""
        self.status_label.config(text=msg)
        self.root.update_idletasks()

    def _copy_to_clipboard(self, text: str) -> bool:
        """Copy text to clipboard. Returns True on success."""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            return True
        except Exception as e:
            self.logger.warning(f"Clipboard operation failed: {e}")
            return False

    def _paste_from_clipboard(self) -> Optional[str]:
        """Paste text from clipboard. Returns text or None on failure."""
        try:
            return self.root.clipboard_get()
        except Exception as e:
            self.logger.warning(f"Clipboard paste failed: {e}")
            return None

    def _run_long_task(self, task):
        """Run a task in a background thread."""
        t = threading.Thread(target=task, daemon=True)
        t.start()

    def _set_analysis_running(self, running: bool):
        """Toggle the analysis-in-progress lock and update the progress bar."""
        self._analysis_running = running
        if running:
            self._status_message(self._t("status_working"))
            self.progress.start(10)
        else:
            self.progress.stop()

    # ------------- VT Analysis Handlers -------------
    def _on_get_report(self):
        if self._analysis_running:
            return
        h = self.entry_hash.get().strip()
        ht = detect_hash_type(h)
        if not ht:
            messagebox.showerror("Error", self._t("err_invalid_hash"))
            return
        # Clear VT analysis, indicators, and raw tabs
        for widget in (self.text_vt_analysis, self.text_raw, self.text_indicators):
            widget.config(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            widget.config(state=tk.DISABLED)

        self._set_analysis_running(True)
        self._run_long_task(lambda: self._process_hash(h, ht))

    def _process_hash(self, h: str, hash_type: str):
        try:
            vt_data = {}
            self._append_vt_analysis(f"[*] {self._t('msg_fetch_file_report')}\n")
            file_report = self.vt_client.get_file_report(h)
            if (file_report.get("ok") is False and file_report.get("status") == 404) or file_report.get("not_found"):
                self._append_vt_analysis(self._t("msg_not_found"))
                self._status_message(self._t("status_done"))
                return
            vt_data["file_report"] = file_report

            # Optional endpoints (behaviour, mitre, comments)
            for key, i18n_fetch_msg, method_name in OPTIONAL_ENDPOINTS:
                self._append_vt_analysis(f"[*] {self._t(i18n_fetch_msg)}\n")
                try:
                    method = getattr(self.vt_client, method_name)
                    if key == "comments":
                        vt_data[key] = method(h, limit=20)
                    else:
                        vt_data[key] = method(h)
                except VTAuthError:
                    self.logger.warning(f"Forbidden: {method_name} for hash {h}")
                    self._append_vt_analysis(f"[!] {method_name} forbidden (403 - insufficient privileges)\n")
                    vt_data[key] = {"ok": False, "status": 403, "error": "forbidden"}
                except Exception as e:
                    self.logger.exception(f"Error calling {method_name}")
                    self._append_vt_analysis(f"[!] {method_name} error: {e}\n")
                    vt_data[key] = {"ok": False, "status": 0, "error": str(e)}

            aggregated = self.aggregator.build_struct(vt_data)
            prompt = self.summarizer.build_prompt(
                self.config.get("llm", {}).get("system_prompt", ""),
                aggregated
            )

            # Populate raw tab with VT composite JSON
            self._append_raw(json.dumps(vt_data, indent=2) + "\n")
            self._append_vt_analysis(f"\n[*] {self._t('msg_llm_start')}\n")

            # LLM streaming
            content_parts = []
            try:
                self.text_vt_analysis.config(state=tk.NORMAL)
                for chunk in self.llm_client.stream_chat(prompt):
                    content_parts.append(chunk)
                    self.text_vt_analysis.insert(tk.END, chunk)
                    self.text_vt_analysis.see(tk.END)
                    time.sleep(0.005)
            except LLMAuthError as e:
                self.logger.error("LLM auth error")
                self._append_vt_analysis(f"\n[!] LLM auth error: {e}\n")
                self._status_message(self._t("status_error"))
                return
            except (LLMBadRequestError, LLMServerError, LLMClientError) as e:
                self.logger.error(f"LLM request error: {e}")
                self._append_vt_analysis(f"\n[!] LLM request failed: {e}\n")
                self._status_message(self._t("status_error"))
                return
            finally:
                self.text_vt_analysis.config(state=tk.DISABLED)

            full = "".join(content_parts)
            parsed_json, free_text = self.summarizer.extract_json_and_text(full)

            # Second LLM call for IOC extraction
            self._append_vt_analysis(f"\n[*] {self._t('msg_ioc_extraction')}\n")
            ioc_summary = self._extract_iocs(aggregated)

            # Store for report saving
            self._last_aggregated = aggregated
            self._last_vt_data = vt_data
            self._last_ioc_summary = ioc_summary

            # Populate indicators tab
            self._build_indicators_tab(ioc_summary, source="vt")

            if parsed_json:
                self._append_vt_analysis(f"\n\nJSON Parsed:\n{json.dumps(parsed_json, indent=2)}\n")
            else:
                self._append_vt_analysis(f"\n\n{self._t('msg_json_parse_fail')}\n")

            self._status_message(self._t("status_done"))
        except Exception as e:
            self.logger.exception("Processing error")
            messagebox.showerror("Error", f"Processing failed: {e}")
            self._status_message(self._t("status_error"))
        finally:
            self._set_analysis_running(False)

    # ------------- File Analysis Handlers -------------
    def _on_browse_file(self):
        """Open file dialog and populate the file path entry."""
        path = filedialog.askopenfilename(title="Select file for analysis")
        if path:
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, path)

    def _on_analyze_file(self):
        """Validate input and start file analysis in a background thread."""
        if self._analysis_running:
            return
        file_path = self.entry_file_path.get().strip()
        if not file_path:
            messagebox.showerror("Error", self._t("err_no_file_selected"))
            return
        if not os.path.isfile(file_path):
            messagebox.showerror("Error", self._t("err_file_not_found"))
            return
        if os.path.getsize(file_path) > 100 * 1024 * 1024:
            messagebox.showerror("Error", self._t("err_file_too_large"))
            return

        # Clear file analysis, indicators, and raw tabs
        for widget in (self.text_file_analysis, self.text_raw, self.text_indicators):
            widget.config(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            widget.config(state=tk.DISABLED)

        self._last_file_analysis_text = ""
        self._set_analysis_running(True)
        self._run_long_task(lambda: self._process_file(file_path))

    def _stream_append(self, chunk: str):
        """Append a streaming LLM chunk to the file analysis text area (must be called from UI thread)."""
        self.text_file_analysis.insert(tk.END, chunk)
        self.text_file_analysis.see(tk.END)

    def _process_file(self, file_path: str):
        """Run the full file analysis pipeline in a background thread."""
        try:
            locale = self.config.get("ui", {}).get("default_language", "en")

            orchestrator = FileAnalysisOrchestrator(
                vt_client=self.vt_client,
                logger=self.logger,
                progress_callback=self._append_file_analysis,
            )

            pipeline_result = orchestrator.run(file_path)
            self._last_file_pipeline_result = pipeline_result

            # Aggregate VT data if available
            vt_aggregated = None
            if pipeline_result.vt_raw:
                try:
                    vt_aggregated = self.aggregator.build_struct(pipeline_result.vt_raw)
                    pipeline_result.vt_aggregated = vt_aggregated
                except Exception as e:
                    self.logger.warning(f"VT aggregation failed: {e}")

            # Populate raw tab with pipeline result JSON
            try:
                raw_payload = {
                    "file_path": file_path,
                    "hashes": pipeline_result.hashes,
                    "vt_raw": pipeline_result.vt_raw or {},
                    "static_analysis": (
                        pipeline_result.static_result.__dict__
                        if pipeline_result.static_result else {}
                    ),
                    "pipeline_errors": pipeline_result.pipeline_errors or [],
                }
                self._append_raw(json.dumps(raw_payload, indent=2, default=str) + "\n")
            except Exception as e:
                self.logger.warning(f"Failed to serialize pipeline result for raw tab: {e}")

            # Build combined LLM context
            self._append_file_analysis(f"[*] {self._t('msg_building_llm_context')}")
            system_prompt = self.config.get("llm", {}).get("system_prompt", "")
            context_builder = CombinedContextBuilder(logger=self.logger)
            prompt = context_builder.build_full_prompt(
                system_prompt=system_prompt,
                pipeline=pipeline_result,
                vt_aggregated=vt_aggregated,
                locale=locale,
            )

            self._append_file_analysis(f"[*] {self._t('msg_llm_start')}")

            # LLM streaming
            content_parts = []
            try:
                self.root.after(0, lambda: self.text_file_analysis.config(state=tk.NORMAL))
                for chunk in self.llm_client.stream_chat(prompt):
                    content_parts.append(chunk)
                    self.root.after(0, self._stream_append, chunk)
                    time.sleep(0.005)
            except LLMAuthError as e:
                self.logger.error("LLM auth error during file analysis")
                self._append_file_analysis(f"\n[!] LLM auth error: {e}")
                self._status_message(self._t("status_error"))
                return
            except (LLMBadRequestError, LLMServerError, LLMClientError) as e:
                self.logger.error(f"LLM request error during file analysis: {e}")
                self._append_file_analysis(f"\n[!] LLM request failed: {e}")
                self._status_message(self._t("status_error"))
                return
            finally:
                self.root.after(0, lambda: self.text_file_analysis.config(state=tk.DISABLED))

            full_response = "".join(content_parts)
            parsed_json, free_text = self.summarizer.extract_json_and_text(full_response)
            if parsed_json:
                self._append_file_analysis(
                    f"\n\nJSON Parsed:\n{json.dumps(parsed_json, indent=2)}"
                )
            else:
                self._append_file_analysis(f"\n\n{self._t('msg_json_parse_fail')}")

            # Store full file analysis text for Copy Summary / Save Report
            self.root.after(0, self._capture_file_analysis_text)

            # Second LLM call for IOC extraction
            self._append_file_analysis(f"\n[*] {self._t('msg_ioc_extraction')}")
            if vt_aggregated:
                ioc_result = self._extract_iocs(vt_aggregated)
            else:
                # Build minimal aggregated structure from static data for IOC extraction
                ioc_result = {"error": "No VT data available for IOC extraction"}

            self._build_indicators_tab(ioc_result, source="file")

            self._status_message(self._t("status_done"))
        except Exception as e:
            self.logger.exception("File analysis pipeline error")
            self._append_file_analysis(f"\n[!] Pipeline error: {e}")
            self._status_message(self._t("status_error"))
        finally:
            # Use root.after to ensure UI cleanup runs on the main thread
            self.root.after(0, lambda: self._set_analysis_running(False))

    def _capture_file_analysis_text(self):
        """Capture the current file analysis text for later copy/save (must run on UI thread)."""
        self._last_file_analysis_text = self.text_file_analysis.get("1.0", tk.END)

    # ------------- Shared Analysis Helpers -------------
    def _build_indicators_tab(self, ioc_result: Dict[str, Any], source: str = "vt"):
        """
        Populate the Indicators/Rules tab with IOC extraction results.

        Args:
            ioc_result: IOC result dict (contains raw_text or error)
            source: "vt" for VT-only analysis, "file" for file analysis
        """
        lines = []
        lines.append("=" * 60)
        if source == "file":
            lines.append("IOC EXTRACTION (AI-assisted from file analysis data)")
        else:
            lines.append("IOC EXTRACTION (AI-assisted from VirusTotal behavior data)")
        lines.append("=" * 60)
        lines.append("")

        if "error" in ioc_result:
            lines.append("⚠ IOC extraction failed:")
            lines.append(f"  {ioc_result['error']}")
            lines.append("")

            self.text_indicators.config(state=tk.NORMAL)
            self.text_indicators.delete("1.0", tk.END)
            self.text_indicators.insert(tk.END, "\n".join(lines))
            self.text_indicators.config(state=tk.DISABLED)
            return

        # Raw mode – display markdown text
        if "raw_text" in ioc_result:
            raw_text = ioc_result.get("raw_text", "")
            attempts = ioc_result.get("attempts", 1)
            model = ioc_result.get("model", "unknown")

            lines.append(f"Model: {model} | Attempts: {attempts}")
            lines.append("")
            lines.append("-" * 60)
            lines.append("")

            self.text_indicators.config(state=tk.NORMAL)
            self.text_indicators.delete("1.0", tk.END)
            self.text_indicators.insert(tk.END, "\n".join(lines))
            self.text_indicators.insert(tk.END, raw_text)
            self.text_indicators.config(state=tk.DISABLED)

            self.logger.info(f"IOC extraction displayed ({len(raw_text)} chars)")
            return

        # Unexpected format fallback
        lines.append("⚠ Unexpected IOC result format")
        lines.append(f"Result keys: {list(ioc_result.keys())}")
        self.text_indicators.config(state=tk.NORMAL)
        self.text_indicators.delete("1.0", tk.END)
        self.text_indicators.insert(tk.END, "\n".join(lines))
        self.text_indicators.config(state=tk.DISABLED)

    def _extract_iocs(self, aggregated: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform the second LLM call to extract IOCs from aggregated data.

        Args:
            aggregated: Aggregated VT data

        Returns:
            IOC result dict for UI display (contains raw_text or error)
        """
        try:
            self.logger.info("Starting IOC extraction")
            result = self.ioc_extractor.run(self.llm_client, aggregated)
            self._last_ioc_result = result
            return result
        except Exception as e:
            self.logger.exception("Unexpected error during IOC extraction")
            return {
                "error": f"Unexpected error: {str(e)}",
                "attempts": 0
            }

    def _append_vt_analysis(self, text: str):
        """Append text to VT-only Analysis textarea (handles readonly state)."""
        self.text_vt_analysis.config(state=tk.NORMAL)
        self.text_vt_analysis.insert(tk.END, text)
        self.text_vt_analysis.see(tk.END)
        self.text_vt_analysis.config(state=tk.DISABLED)

    def _append_raw(self, text: str):
        """Append text to Raw textarea (handles readonly state)."""
        self.text_raw.config(state=tk.NORMAL)
        self.text_raw.insert(tk.END, text)
        self.text_raw.see(tk.END)
        self.text_raw.config(state=tk.DISABLED)

    def _append_file_analysis(self, text: str):
        """Append text to the File Analysis textarea (thread-safe via after)."""
        def _do():
            self.text_file_analysis.config(state=tk.NORMAL)
            self.text_file_analysis.insert(tk.END, text if text.endswith("\n") else text + "\n")
            self.text_file_analysis.see(tk.END)
            self.text_file_analysis.config(state=tk.DISABLED)
        self.root.after(0, _do)

    # ------------- Clipboard Handlers -------------
    def _on_clear_hash(self):
        """Clear the hash input field."""
        self.entry_hash.delete(0, tk.END)
        self._status_message(self._t("msg_cleared"))

    def _on_copy_hash(self):
        """Copy hash from input field to clipboard."""
        text = self.entry_hash.get()
        if self._copy_to_clipboard(text):
            self._status_message(self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    def _on_paste_hash(self):
        """Paste hash from clipboard to input field."""
        text = self._paste_from_clipboard()
        if text:
            self.entry_hash.delete(0, tk.END)
            self.entry_hash.insert(0, text.strip())
            self._status_message(self._t("msg_pasted"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    def _on_copy_vt_summary(self):
        """Copy VT-only Analysis text to clipboard."""
        txt = self.text_vt_analysis.get("1.0", tk.END)
        if self._copy_to_clipboard(txt):
            messagebox.showinfo(self._t("btn_copy"), self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    def _on_copy_file_summary(self):
        """Copy File Analysis text to clipboard."""
        txt = self.text_file_analysis.get("1.0", tk.END)
        if self._copy_to_clipboard(txt):
            messagebox.showinfo(self._t("btn_copy"), self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    def _on_copy_indicators(self):
        """Copy Indicators/Rules text to clipboard."""
        txt = self.text_indicators.get("1.0", tk.END)
        if self._copy_to_clipboard(txt):
            messagebox.showinfo(self._t("btn_copy"), self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    def _on_copy_raw(self):
        """Copy Raw text to clipboard."""
        txt = self.text_raw.get("1.0", tk.END)
        if self._copy_to_clipboard(txt):
            messagebox.showinfo(self._t("btn_copy"), self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    # ------------- Report Save Handlers -------------
    def _on_save_vt_report(self):
        """Save the VT-only analysis result as JSON + TXT reports."""
        content_summary = self.text_vt_analysis.get("1.0", tk.END).strip()
        raw_json_text = self.text_raw.get("1.0", tk.END).strip()

        vt_data = self._last_vt_data or {}
        if not vt_data:
            try:
                vt_data = json.loads(raw_json_text) if raw_json_text else {}
            except Exception:
                vt_data = {}

        parsed_json = None
        free_text = content_summary
        json_candidate = self.summarizer.extract_first_json_block(content_summary)
        if json_candidate:
            try:
                parsed_json = json.loads(json_candidate)
                free_text = content_summary.replace(json_candidate, "", 1).strip()
            except Exception:
                pass

        hash_input = self.entry_hash.get().strip()
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        out_dir = self.config.get("output", {}).get("directory", "reports")
        os.makedirs(out_dir, exist_ok=True)

        report_obj = {
            "hash": hash_input,
            "timestamp_utc": ts,
            "vt_raw": vt_data,
            "summary": {
                **(parsed_json or {}),
                "free_text": free_text
            },
            "ioc_summary": self._last_ioc_result or {"error": "IOC extraction not performed or failed"},
            "meta": {
                "generator": "JUMAL 0.1",
                "analysis_type": "vt_only",
                "llm_model": self.config.get("llm", {}).get("model"),
                "ioc_model": self.config.get("llm", {}).get("ioc_model"),
                "vt_base_url": self.config.get("virustotal", {}).get("base_url")
            }
        }

        label = hash_input or "unknown"
        json_path = os.path.join(out_dir, f"report_{label}_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_obj, f, indent=2, ensure_ascii=False)

        txt_path = os.path.join(out_dir, f"report_{label}_{ts}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(content_summary)

        messagebox.showinfo(self._t("msg_saved"), f"{self._t('msg_saved')}\n{json_path}\n{txt_path}")

    def _on_save_file_report(self):
        """Save the File Analysis result as JSON + TXT reports."""
        content_text = self.text_file_analysis.get("1.0", tk.END).strip()
        indicators_text = self.text_indicators.get("1.0", tk.END).strip()
        raw_text = self.text_raw.get("1.0", tk.END).strip()

        pipeline = self._last_file_pipeline_result
        file_label = "unknown"
        if pipeline and pipeline.hashes:
            file_label = pipeline.hashes.get("sha256") or pipeline.hashes.get("md5") or "unknown"

        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        out_dir = self.config.get("output", {}).get("directory", "reports")
        os.makedirs(out_dir, exist_ok=True)

        report_obj = {
            "file_label": file_label,
            "timestamp_utc": ts,
            "hashes": pipeline.hashes if pipeline else {},
            "vt_raw": pipeline.vt_raw if pipeline else {},
            "analysis_text": content_text,
            "ioc_summary": self._last_ioc_result or {"error": "IOC extraction not performed or failed"},
            "indicators_text": indicators_text,
            "raw_text": raw_text,
            "meta": {
                "generator": "JUMAL 0.1",
                "analysis_type": "file_analysis",
                "llm_model": self.config.get("llm", {}).get("model"),
                "ioc_model": self.config.get("llm", {}).get("ioc_model"),
            }
        }

        json_path = os.path.join(out_dir, f"file_report_{file_label[:16]}_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_obj, f, indent=2, ensure_ascii=False, default=str)

        txt_path = os.path.join(out_dir, f"file_report_{file_label[:16]}_{ts}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(content_text)

        messagebox.showinfo(self._t("msg_saved"), f"{self._t('msg_saved')}\n{json_path}\n{txt_path}")

    def run(self):
        self.root.mainloop()
