import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
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
        
        # Store for report saving
        self._last_aggregated = None
        self._last_vt_data = None
        self._last_ioc_summary = None
        self._last_ioc_result = None

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
        self.frame_summary = ttk.Frame(self.notebook)
        self.frame_indicators = ttk.Frame(self.notebook)
        self.frame_raw = ttk.Frame(self.notebook)
        self.frame_config = ttk.Frame(self.notebook)

        self.notebook.add(self.frame_summary, text=self._t("tab_summary"))
        self.notebook.add(self.frame_indicators, text=self._t("tab_indicators"))
        self.notebook.add(self.frame_raw, text=self._t("tab_raw"))
        self.notebook.add(self.frame_config, text=self._t("tab_config"))
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Summary top controls
        top_frame = ttk.Frame(self.frame_summary)
        top_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Label(top_frame, text=self._t("label_hash")).pack(side=tk.LEFT)
        self.entry_hash = ttk.Entry(top_frame, width=60)
        self.entry_hash.pack(side=tk.LEFT, padx=5)
        
        # Hash actions: Clear, Copy, Paste
        ttk.Button(top_frame, text=self._t("btn_clear"), command=self._on_clear_hash, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text=self._t("btn_copy"), command=self._on_copy_hash, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text=self._t("btn_paste"), command=self._on_paste_hash, width=6).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(top_frame, text=self._t("btn_get_report"), command=self._on_get_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text=self._t("btn_copy_summary"), command=self._on_copy_summary).pack(side=tk.LEFT)
        ttk.Button(top_frame, text=self._t("btn_save_report"), command=self._on_save_report).pack(side=tk.LEFT, padx=5)

        self.text_summary = scrolledtext.ScrolledText(self.frame_summary, wrap=tk.WORD, state=tk.DISABLED)
        self.text_summary.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Indicators / Rules tab
        indicators_top_frame = ttk.Frame(self.frame_indicators)
        indicators_top_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Button(indicators_top_frame, text=self._t("btn_copy_indicators"), command=self._on_copy_indicators).pack(side=tk.LEFT)
        
        self.text_indicators = scrolledtext.ScrolledText(self.frame_indicators, wrap=tk.WORD, state=tk.DISABLED)
        self.text_indicators.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Raw tab
        raw_top_frame = ttk.Frame(self.frame_raw)
        raw_top_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Button(raw_top_frame, text=self._t("btn_copy_raw"), command=self._on_copy_raw).pack(side=tk.LEFT)
        
        self.text_raw = scrolledtext.ScrolledText(self.frame_raw, wrap=tk.WORD, state=tk.DISABLED)
        self.text_raw.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Config tab
        cfg_frame = ttk.Frame(self.frame_config)
        cfg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.var_vt_key = tk.StringVar(value=self.config.get("virustotal", {}).get("api_key", ""))
        self.var_vt_base_url = tk.StringVar(value=self.config.get("virustotal", {}).get("base_url", "https://www.virustotal.com/api/v3"))
        self.var_llm_key = tk.StringVar(value=self.config.get("llm", {}).get("api_key", ""))
        self.var_llm_provider_url = tk.StringVar(value=self.config.get("llm", {}).get("provider_url", "https://openrouter.ai/api/v1"))
        self.var_llm_model = tk.StringVar(value=self.config.get("llm", {}).get("model", "meta-llama/llama-3.2-1b-instruct"))
        self.var_ioc_model = tk.StringVar(value=self.config.get("llm", {}).get("ioc_model", ""))
        self.var_user_agent = tk.StringVar(value=self.config.get("network", {}).get("user_agent", "JUMAL/0.1"))
        self.var_system_prompt = tk.StringVar(value=self.config.get("llm", {}).get("system_prompt", ""))
        self.var_ioc_system_prompt = tk.StringVar(value=self.config.get("llm", {}).get("ioc_raw_system_prompt", ""))
        self.var_ioc_user_template = tk.StringVar(value=self.config.get("llm", {}).get("ioc_raw_user_template", ""))
        self.var_lang = tk.StringVar(value=self.current_lang)

        row = 0
        for label, var in [
            (self._t("cfg_vt_api_key"), self.var_vt_key),
            (self._t("cfg_vt_base_url"), self.var_vt_base_url),
            (self._t("cfg_llm_api_key"), self.var_llm_key),
            (self._t("cfg_llm_provider_url"), self.var_llm_provider_url),
            (self._t("cfg_llm_model"), self.var_llm_model),
            (self._t("cfg_ioc_model"), self.var_ioc_model),
            (self._t("cfg_user_agent"), self.var_user_agent),
        ]:
            ttk.Label(cfg_frame, text=label).grid(row=row, column=0, sticky="w", pady=2)
            ttk.Entry(cfg_frame, textvariable=var, width=60).grid(row=row, column=1, sticky="w", pady=2)
            row += 1

        # System prompt
        ttk.Label(cfg_frame, text=self._t("cfg_system_prompt")).grid(row=row, column=0, sticky="nw", pady=2)
        self.system_prompt_box = tk.Text(cfg_frame, height=5, width=60)
        self.system_prompt_box.grid(row=row, column=1, sticky="w", pady=2)
        self.system_prompt_box.insert("1.0", self.var_system_prompt.get())
        row += 1

        # IOC System prompt
        ttk.Label(cfg_frame, text=self._t("cfg_ioc_system_prompt")).grid(row=row, column=0, sticky="nw", pady=2)
        self.ioc_system_prompt_box = tk.Text(cfg_frame, height=5, width=60)
        self.ioc_system_prompt_box.grid(row=row, column=1, sticky="w", pady=2)
        self.ioc_system_prompt_box.insert("1.0", self.var_ioc_system_prompt.get())
        row += 1

        # IOC User template
        ttk.Label(cfg_frame, text=self._t("cfg_ioc_user_template")).grid(row=row, column=0, sticky="nw", pady=2)
        self.ioc_user_template_box = tk.Text(cfg_frame, height=8, width=60)
        self.ioc_user_template_box.grid(row=row, column=1, sticky="w", pady=2)
        self.ioc_user_template_box.insert("1.0", self.var_ioc_user_template.get())
        row += 1

        # Language selector
        ttk.Label(cfg_frame, text=self._t("cfg_language")).grid(row=row, column=0, sticky="w", pady=2)
        lang_cb = ttk.Combobox(cfg_frame, textvariable=self.var_lang, values=list(self.lang_data.keys()), width=10)
        lang_cb.grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        # Apply and Reset buttons
        btn_frame = ttk.Frame(cfg_frame)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=10, sticky="w")
        ttk.Button(btn_frame, text=self._t("btn_apply"), command=self._on_apply_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=self._t("btn_reset"), command=self._on_reset_config).pack(side=tk.LEFT, padx=5)
        ttk.Label(btn_frame, text=self._t("disclaimer")).pack(side=tk.LEFT, padx=10)
        row += 1

        # Status bar
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_label = ttk.Label(status_frame, text="")
        self.status_label.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress.pack(side=tk.RIGHT, padx=5)

    # ------------- Helpers -------------
    def _status_message(self, msg: str):
        """Display a status message in the status bar."""
        self.status_label.config(text=msg)
        self.root.update_idletasks()

    def _copy_to_clipboard(self, text: str) -> bool:
        """
        Copy text to clipboard with fallback.
        
        Args:
            text: Text to copy
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()  # Ensure clipboard is updated
            return True
        except Exception as e:
            self.logger.warning(f"Clipboard operation failed: {e}")
            return False

    def _paste_from_clipboard(self) -> Optional[str]:
        """
        Paste text from clipboard with fallback.
        
        Returns:
            Clipboard text or None if failed
        """
        try:
            return self.root.clipboard_get()
        except Exception as e:
            self.logger.warning(f"Clipboard paste failed: {e}")
            return None

    def _run_long_task(self, task):
        """Run a task in a background thread."""
        t = threading.Thread(target=task, daemon=True)
        t.start()

    # ------------- Event Handlers -------------
    def _on_get_report(self):
        h = self.entry_hash.get().strip()
        ht = detect_hash_type(h)
        if not ht:
            messagebox.showerror("Error", self._t("err_invalid_hash"))
            return
        # Clear readonly textareas
        self.text_summary.config(state=tk.NORMAL)
        self.text_summary.delete("1.0", tk.END)
        self.text_summary.config(state=tk.DISABLED)
        
        self.text_raw.config(state=tk.NORMAL)
        self.text_raw.delete("1.0", tk.END)
        self.text_raw.config(state=tk.DISABLED)
        
        self.text_indicators.config(state=tk.NORMAL)
        self.text_indicators.delete("1.0", tk.END)
        self.text_indicators.config(state=tk.DISABLED)
        
        self._status_message(self._t("status_working"))
        self.progress.start(10)
        self._run_long_task(lambda: self._process_hash(h, ht))

    def _process_hash(self, h: str, hash_type: str):
        try:
            vt_data = {}
            self._append_summary(f"[*] {self._t('msg_fetch_file_report')}\n")
            file_report = self.vt_client.get_file_report(h)
            if (file_report.get("ok") is False and file_report.get("status") == 404) or file_report.get("not_found"):
                self._append_summary(self._t("msg_not_found"))
                self._status_message(self._t("status_done"))
                self.progress.stop()
                return
            vt_data["file_report"] = file_report

            # Optional endpoints (behaviour, mitre, comments)
            for key, i18n_fetch_msg, method_name in OPTIONAL_ENDPOINTS:
                self._append_summary(f"[*] {self._t(i18n_fetch_msg)}\n")
                try:
                    method = getattr(self.vt_client, method_name)
                    if key == "comments":
                        vt_data[key] = method(h, limit=20)
                    else:
                        vt_data[key] = method(h)
                except VTAuthError:
                    self.logger.warning(f"Forbidden: {method_name} for hash {h}")
                    self._append_summary(f"[!] {method_name} forbidden (403 - insufficient privileges)\n")
                    vt_data[key] = {"ok": False, "status": 403, "error": "forbidden"}
                except Exception as e:
                    self.logger.exception(f"Error calling {method_name}")
                    self._append_summary(f"[!] {method_name} error: {e}\n")
                    vt_data[key] = {"ok": False, "status": 0, "error": str(e)}

            aggregated = self.aggregator.build_struct(vt_data)
            prompt = self.summarizer.build_prompt(
                self.config.get("llm", {}).get("system_prompt", ""),
                aggregated
            )

            # Show raw VT composite
            self._append_raw(json.dumps(vt_data, indent=2) + "\n")
            self._append_summary(f"\n[*] {self._t('msg_llm_start')}\n")

            # LLM streaming
            content_parts = []
            try:
                self.text_summary.config(state=tk.NORMAL)  # Enable for streaming
                for chunk in self.llm_client.stream_chat(prompt):
                    content_parts.append(chunk)
                    self.text_summary.insert(tk.END, chunk)
                    self.text_summary.see(tk.END)
                    # slight pause for UI responsiveness
                    time.sleep(0.005)
            except LLMAuthError as e:
                self.logger.error("LLM auth error")
                self._append_summary(f"\n[!] LLM auth error: {e}\n")
                self._status_message(self._t("status_error"))
                self.progress.stop()
                return
            except (LLMBadRequestError, LLMServerError, LLMClientError) as e:
                self.logger.error(f"LLM request error: {e}")
                self._append_summary(f"\n[!] LLM request failed: {e}\n")
                self._status_message(self._t("status_error"))
                self.progress.stop()
                return
            finally:
                self.text_summary.config(state=tk.DISABLED)  # Always disable after streaming

            full = "".join(content_parts)
            parsed_json, free_text = self.summarizer.extract_json_and_text(full)

            # Second LLM call for IOC extraction
            self._append_summary(f"\n[*] {self._t('msg_ioc_extraction')}\n")
            ioc_summary = self._extract_iocs(aggregated)
            
            # Store for report saving
            self._last_aggregated = aggregated
            self._last_vt_data = vt_data
            self._last_ioc_summary = ioc_summary

            # Indicators tab build with IOC extraction results
            self._build_indicators_tab(ioc_summary)

            if parsed_json:
                self._append_summary(f"\n\nJSON Parsed:\n{json.dumps(parsed_json, indent=2)}\n")
            else:
                self._append_summary(f"\n\n{self._t('msg_json_parse_fail')}\n")

            self._status_message(self._t("status_done"))
        except Exception as e:
            self.logger.exception("Processing error")
            messagebox.showerror("Error", f"Processing failed: {e}")
            self._status_message(self._t("status_error"))
        finally:
            self.progress.stop()

    def _build_indicators_tab(self, ioc_result: Dict[str, Any]):
        """
        Build Indicators/Rules tab with IOC data from LLM extraction.
        
        Args:
            ioc_result: IOC result dict (contains raw_text or error)
        """
        lines = []
        lines.append("=" * 60)
        lines.append("IOC EXTRACTION (AI-assisted from VirusTotal behavior data)")
        lines.append("=" * 60)
        lines.append("")
        
        # Check if there was an error
        if "error" in ioc_result:
            lines.append("⚠ IOC extraction failed:")
            lines.append(f"  {ioc_result['error']}")
            lines.append("")
            
            self.text_indicators.config(state=tk.NORMAL)
            self.text_indicators.delete("1.0", tk.END)
            self.text_indicators.insert(tk.END, "\n".join(lines))
            self.text_indicators.config(state=tk.DISABLED)
            return
        
        # Raw mode - display markdown text
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
            
            self.logger.info(f"IOC extraction displayed successfully ({len(raw_text)} chars)")
            return
        
        # Fallback for unexpected format
        lines.append("⚠ Unexpected IOC result format")
        lines.append(f"Result keys: {list(ioc_result.keys())}")
        self.text_indicators.config(state=tk.NORMAL)
        self.text_indicators.delete("1.0", tk.END)
        self.text_indicators.insert(tk.END, "\n".join(lines))
        self.text_indicators.config(state=tk.DISABLED)
    
    def _extract_iocs(self, aggregated: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform second LLM call to extract IOCs.
        
        Args:
            aggregated: Aggregated VT data
            
        Returns:
            IOC result dict for UI display (contains raw_text or error)
        """
        try:
            # Use the new run() method
            self.logger.info("Starting IOC extraction")
            result = self.ioc_extractor.run(self.llm_client, aggregated)
            
            # Store full result for report saving
            self._last_ioc_result = result
            
            # Return result as-is (contains raw_text or error)
            return result
        
        except Exception as e:
            self.logger.exception("Unexpected error during IOC extraction")
            return {
                "error": f"Unexpected error: {str(e)}",
                "attempts": 0
            }

    def _append_summary(self, text: str):
        """Append text to summary textarea (handles readonly state)."""
        self.text_summary.config(state=tk.NORMAL)
        self.text_summary.insert(tk.END, text)
        self.text_summary.see(tk.END)
        self.text_summary.config(state=tk.DISABLED)

    def _append_raw(self, text: str):
        """Append text to raw textarea (handles readonly state)."""
        self.text_raw.config(state=tk.NORMAL)
        self.text_raw.insert(tk.END, text)
        self.text_raw.see(tk.END)
        self.text_raw.config(state=tk.DISABLED)

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

    def _on_copy_summary(self):
        """Copy summary text to clipboard."""
        txt = self.text_summary.get("1.0", tk.END)
        if self._copy_to_clipboard(txt):
            messagebox.showinfo(self._t("btn_copy"), self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))
    
    def _on_copy_indicators(self):
        """Copy indicators text to clipboard."""
        txt = self.text_indicators.get("1.0", tk.END)
        if self._copy_to_clipboard(txt):
            messagebox.showinfo(self._t("btn_copy"), self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    def _on_copy_raw(self):
        """Copy raw text to clipboard."""
        txt = self.text_raw.get("1.0", tk.END)
        if self._copy_to_clipboard(txt):
            messagebox.showinfo(self._t("btn_copy"), self._t("msg_copied"))
        else:
            messagebox.showerror(self._t("status_error"), self._t("err_clipboard"))

    def _on_save_report(self):
        content_summary = self.text_summary.get("1.0", tk.END).strip()
        raw_json_text = self.text_raw.get("1.0", tk.END).strip()
        
        # Use stored data if available
        if self._last_vt_data:
            vt_data = self._last_vt_data
        else:
            try:
                vt_data = json.loads(raw_json_text) if raw_json_text else {}
            except Exception:
                vt_data = {}

        # Use Summarizer's improved JSON extraction method
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
        if not os.path.exists(out_dir):
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
                "llm_model": self.config.get("llm", {}).get("model"),
                "ioc_model": self.config.get("llm", {}).get("ioc_model"),
                "vt_base_url": self.config.get("virustotal", {}).get("base_url")
            }
        }

        json_path = os.path.join(out_dir, f"report_{hash_input}_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_obj, f, indent=2, ensure_ascii=False)

        txt_path = os.path.join(out_dir, f"report_{hash_input}_{ts}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(content_summary)

        messagebox.showinfo("Saved", f"Saved:\n{json_path}\n{txt_path}")

    def _on_apply_config(self):
        """Apply configuration changes from UI."""
        # Validate required fields
        if not self.var_vt_key.get().strip():
            messagebox.showerror(self._t("status_error"), 
                                f"{self._t('cfg_vt_api_key')}: {self._t('err_validation_required')}")
            return
        if not self.var_llm_key.get().strip():
            messagebox.showerror(self._t("status_error"),
                                f"{self._t('cfg_llm_api_key')}: {self._t('err_validation_required')}")
            return
        
        new_cfg = {
            "virustotal": {
                "api_key": self.var_vt_key.get(),
                "base_url": self.var_vt_base_url.get()
            },
            "llm": {
                "api_key": self.var_llm_key.get(),
                "provider_url": self.var_llm_provider_url.get(),
                "model": self.var_llm_model.get(),
                "ioc_model": self.var_ioc_model.get() if self.var_ioc_model.get().strip() else None,
                "system_prompt": self.system_prompt_box.get('1.0', tk.END).strip(),
                "ioc_raw_system_prompt": self.ioc_system_prompt_box.get('1.0', tk.END).strip(),
                "ioc_raw_user_template": self.ioc_user_template_box.get('1.0', tk.END).strip()
            },
            "network": {
                "user_agent": self.var_user_agent.get()
            },
            "ui": {
                "default_language": self.var_lang.get()
            }
        }
        self.cfg_manager.update_from_dict(new_cfg)
        self.config = self.cfg_manager.get()
        self.current_lang = self.config.get("ui", {}).get("default_language", "en")
        
        # Reinitialize components with new config
        self.summarizer = Summarizer(self.logger, self.config)
        self.ioc_extractor = IOCExtractor(self.logger, self.config)
        
        self._status_message(self._t("status_applied"))
        self._init_clients()
        messagebox.showinfo(self._t("btn_apply"), self._t("msg_saved"))

    def _on_reset_config(self):
        """Reset configuration fields to currently saved values."""
        self.var_vt_key.set(self.config.get("virustotal", {}).get("api_key", ""))
        self.var_vt_base_url.set(self.config.get("virustotal", {}).get("base_url", "https://www.virustotal.com/api/v3"))
        self.var_llm_key.set(self.config.get("llm", {}).get("api_key", ""))
        self.var_llm_provider_url.set(self.config.get("llm", {}).get("provider_url", "https://openrouter.ai/api/v1"))
        self.var_llm_model.set(self.config.get("llm", {}).get("model", "meta-llama/llama-3.2-1b-instruct"))
        self.var_ioc_model.set(self.config.get("llm", {}).get("ioc_model", ""))
        self.var_user_agent.set(self.config.get("network", {}).get("user_agent", "JUMAL/0.1"))
        self.var_lang.set(self.current_lang)
        
        # Reset text boxes
        self.system_prompt_box.delete("1.0", tk.END)
        self.system_prompt_box.insert("1.0", self.config.get("llm", {}).get("system_prompt", ""))
        
        self.ioc_system_prompt_box.delete("1.0", tk.END)
        self.ioc_system_prompt_box.insert("1.0", self.config.get("llm", {}).get("ioc_raw_system_prompt", ""))
        
        self.ioc_user_template_box.delete("1.0", tk.END)
        self.ioc_user_template_box.insert("1.0", self.config.get("llm", {}).get("ioc_raw_user_template", ""))
        
        self._status_message(self._t("status_reset"))
        messagebox.showinfo(self._t("btn_reset"), self._t("status_reset"))

    def run(self):
        self.root.mainloop()
