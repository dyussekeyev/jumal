import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
import os
from typing import Dict, Any
from core.hashutil import detect_hash_type
from clients.vt_client import VTClient, VTAuthError
from clients.llm_client import LLMClient
from core.aggregator import Aggregator
from core.summarizer import Summarizer

OPTIONAL_ENDPOINTS = [
    ("behaviour", "msg_fetch_behaviour", "get_behaviour"),
    ("behaviour_mitre_trees", "msg_fetch_mitre", "get_behaviour_mitre_trees"),
    ("yara_ruleset", "msg_fetch_yara", "get_yara_ruleset"),
    ("sigma_rules", "msg_fetch_sigma", "get_sigma_rules")
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
        self.summarizer = Summarizer(self.logger)
        self._init_clients()

        self._progress_stage = tk.StringVar(value="Idle")
        self._status_message(self._t("status_idle"))

    # i18n
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
            base_url=llm_cfg.get("provider_url", "https://api.openai.com/v1"),
            api_key=llm_cfg.get("api_key", ""),
            model=llm_cfg.get("model", "gpt-4o-mini"),
            stream_enabled=llm_cfg.get("stream_enabled", True),
            timeout=net_cfg.get("request_timeout_seconds", 30),
            logger=self.logger
        )

    def _init_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.frame_summary = ttk.Frame(self.notebook)
        self.frame_indicators = ttk.Frame(self.notebook)
        self.frame_raw = ttk.Frame(self.notebook)
        self.frame_config = ttk.Frame(self.notebook)

        self.notebook.add(self.frame_summary, text="Summary")
        self.notebook.add(self.frame_indicators, text="Indicators/Rules")
        self.notebook.add(self.frame_raw, text="Raw")
        self.notebook.add(self.frame_config, text="Config")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Top panel summary
        top_frame = ttk.Frame(self.frame_summary)
        top_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Label(top_frame, text=self._t("label_hash")).pack(side=tk.LEFT)
        self.entry_hash = ttk.Entry(top_frame, width=60)
        self.entry_hash.pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text=self._t("btn_get_report"), command=self._on_get_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text=self._t("btn_copy_summary"), command=self._on_copy_summary).pack(side=tk.LEFT)
        ttk.Button(top_frame, text=self._t("btn_save_report"), command=self._on_save_report).pack(side=tk.LEFT, padx=5)

        self.text_summary = scrolledtext.ScrolledText(self.frame_summary, wrap=tk.WORD)
        self.text_summary.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_indicators = scrolledtext.ScrolledText(self.frame_indicators, wrap=tk.WORD)
        self.text_indicators.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_raw = scrolledtext.ScrolledText(self.frame_raw, wrap=tk.WORD)
        self.text_raw.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Config tab
        cfg_frame = ttk.Frame(self.frame_config)
        cfg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.var_vt_key = tk.StringVar(value=self.config.get("virustotal", {}).get("api_key", ""))
        self.var_llm_key = tk.StringVar(value=self.config.get("llm", {}).get("api_key", ""))
        self.var_llm_model = tk.StringVar(value=self.config.get("llm", {}).get("model", "gpt-4o-mini"))
        self.var_user_agent = tk.StringVar(value=self.config.get("network", {}).get("user_agent", "JUMAL/0.1"))
        self.var_system_prompt = tk.StringVar(value=self.config.get("llm", {}).get("system_prompt", ""))
        self.var_lang = tk.StringVar(value=self.current_lang)

        row = 0
        for label, var in [
            (self._t("cfg_vt_api_key"), self.var_vt_key),
            (self._t("cfg_llm_api_key"), self.var_llm_key),
            (self._t("cfg_llm_model"), self.var_llm_model),
            (self._t("cfg_user_agent"), self.var_user_agent),
        ]:
            ttk.Label(cfg_frame, text=label).grid(row=row, column=0, sticky="w")
            ttk.Entry(cfg_frame, textvariable=var, width=60).grid(row=row, column=1, sticky="w", pady=2)
            row += 1

        ttk.Label(cfg_frame, text=self._t("cfg_system_prompt")).grid(row=row, column=0, sticky="nw")
        tk.Text(cfg_frame, height=5, width=60, name="system_prompt_box").grid(row=row, column=1, sticky="w", pady=2)
        self.system_prompt_box = cfg_frame.children["system_prompt_box"]
        self.system_prompt_box.insert("1.0", self.var_system_prompt.get())
        row += 1

        ttk.Label(cfg_frame, text=self._t("cfg_language")).grid(row=row, column=0, sticky="w")
        lang_cb = ttk.Combobox(cfg_frame, textvariable=self.var_lang, values=list(self.lang_data.keys()), width=10)
        lang_cb.grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Button(cfg_frame, text=self._t("btn_apply"), command=self._on_apply_config).grid(row=row, column=0, pady=10)
        ttk.Label(cfg_frame, text=self._t("disclaimer")).grid(row=row, column=1, sticky="w")
        row += 1

        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_label = ttk.Label(status_frame, text="")
        self.status_label.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress.pack(side=tk.RIGHT, padx=5)

    def _status_message(self, msg: str):
        self.status_label.config(text=msg)
        self.root.update_idletasks()

    def _run_long_task(self, task):
        t = threading.Thread(target=task, daemon=True)
        t.start()

    def _on_get_report(self):
        h = self.entry_hash.get().strip()
        ht = detect_hash_type(h)
        if not ht:
            messagebox.showerror("Error", self._t("err_invalid_hash"))
            return
        self.text_summary.delete("1.0", tk.END)
        self.text_raw.delete("1.0", tk.END)
        self.text_indicators.delete("1.0", tk.END)
        self._status_message(self._t("status_working"))
        self.progress.start(10)
        self._run_long_task(lambda: self._process_hash(h, ht))

    def _process_hash(self, h: str, hash_type: str):
        try:
            vt_data = {}
            self._append_summary(f"[*] {self._t('msg_fetch_file_report')}\n")
            file_report = self.vt_client.get_file_report(h)
            if file_report.get("ok") is False and file_report.get("status") == 404 or file_report.get("not_found"):
                self._append_summary(self._t("msg_not_found"))
                self._status_message(self._t("status_done"))
                self.progress.stop()
                return
            vt_data["file_report"] = file_report

            # Optional endpoints (graceful degradation)
            for key, i18n_fetch_msg, method_name in OPTIONAL_ENDPOINTS:
                self._append_summary(f"[*] {self._t(i18n_fetch_msg)}\n")
                try:
                    method = getattr(self.vt_client, method_name)
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
            prompt = self.summarizer.build_prompt(self.config.get("llm", {}).get("system_prompt", ""), aggregated)

            self._append_raw(json.dumps(vt_data, indent=2) + "\n")
            self._append_summary(f"\n[*] {self._t('msg_llm_start')}\n")

            # LLM streaming
            content_parts = []
            for chunk in self.llm_client.stream_chat(prompt):
                content_parts.append(chunk)
                self.text_summary.insert(tk.END, chunk)
                self.text_summary.see(tk.END)
                time.sleep(0.005)
            full = "".join(content_parts)
            parsed_json, free_text = self.summarizer.extract_json_and_text(full)

            self._build_indicators_tab(aggregated)

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

    def _build_indicators_tab(self, aggregated: Dict[str, Any]):
        lines = []
        lines.append("Processes:")
        for p in aggregated.get("processes", []):
            lines.append(f"- {p}")
        lines.append("\nNetwork:")
        for n in aggregated.get("network", []):
            lines.append(f"- {n}")
        lines.append("\nYARA:")
        yr = aggregated.get("yara_ruleset")
        lines.append(("(none)" if not yr else json.dumps(yr)[:2000]))
        lines.append("\nSIGMA:")
        sr = aggregated.get("sigma_rules")
        lines.append(("(none)" if not sr else json.dumps(sr)[:2000]))
        self.text_indicators.insert(tk.END, "\n".join(lines))

    def _append_summary(self, text: str):
        self.text_summary.insert(tk.END, text)
        self.text_summary.see(tk.END)

    def _append_raw(self, text: str):
        self.text_raw.insert(tk.END, text)
        self.text_raw.see(tk.END)

    def _on_copy_summary(self):
        txt = self.text_summary.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        messagebox.showinfo("Copied", self._t("msg_copied"))

    def _on_save_report(self):
        content_summary = self.text_summary.get("1.0", tk.END).strip()
        raw_json_text = self.text_raw.get("1.0", tk.END).strip()
        try:
            vt_data = json.loads(raw_json_text) if raw_json_text else {}
        except Exception:
            vt_data = {}

        parsed_json = None
        free_text = content_summary
        import re, json as _json
        m = re.search(r"\{.*?\}", content_summary, re.DOTALL)
        if m:
            try:
                parsed_json = _json.loads(m.group(0))
                free_text = content_summary.replace(m.group(0), "").strip()
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
            "meta": {
                "generator": "JUMAL 0.1",
                "llm_model": self.config.get("llm", {}).get("model"),
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
        new_cfg = {
            "virustotal": {
                "api_key": self.var_vt_key.get()
            },
            "llm": {
                "api_key": self.var_llm_key.get(),
                "model": self.var_llm_model.get(),
                "system_prompt": self.system_prompt_box.get('1.0', tk.END).strip()
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
        self._status_message(self._t("status_applied"))
        self._init_clients()

    def run(self):
        self.root.mainloop()
