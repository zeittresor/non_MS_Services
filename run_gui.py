# non_MS_Services_audit_tool
# source: github.com/zeittresor

import os
import re
import csv
import json
import time
import hashlib
import datetime
import subprocess
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import win32service
import win32api


class Tooltip:
    """Simple Tkinter tooltip for widgets."""
    def __init__(self, widget, text: str, delay_ms: int = 350):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id = None
        self._tip = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)

    def _schedule(self, _event=None):
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _show(self):
        if self._tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        lbl = ttk.Label(self._tip, text=self.text, padding=(10, 6))
        lbl.pack()

    def _hide(self, _event=None):
        if self._after_id:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        if self._tip:
            self._tip.destroy()
            self._tip = None


def parse_service_image_path(raw: str) -> str:
    """Extract executable path from a service BinaryPathName string."""
    if not raw:
        return ""
    s = os.path.expandvars(raw.strip())
    if s.startswith('"'):
        m = re.match(r'^"([^"]+)"', s)
        return m.group(1) if m else ""
    parts = s.split()
    return parts[0].strip('"') if parts else ""


def get_file_company_name(path: str) -> str:
    """Return CompanyName from version resources when available."""
    try:
        info = win32api.GetFileVersionInfo(path, "\\VarFileInfo\\Translation")
        if not info:
            return ""
        lang, codepage = info[0]
        str_info_path = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\CompanyName"
        return win32api.GetFileVersionInfo(path, str_info_path) or ""
    except Exception:
        return ""


def authenticode_signer_subject(path: str) -> tuple[str, str]:
    """Return (Status, SignerSubject) using PowerShell Get-AuthenticodeSignature.

    Reads stdout as bytes and decodes safely to avoid Windows codepage UnicodeDecodeError.
    """
    ps_cmd = (
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
        "$sig = Get-AuthenticodeSignature -FilePath $args[0]; "
        "$st = $sig.Status.ToString(); "
        "$sub = ''; "
        "if ($sig.SignerCertificate -ne $null) { $sub = $sig.SignerCertificate.Subject } "
        "Write-Output ($st + '|' + $sub)"
    )
    ps = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_cmd,
        path,
    ]
    try:
        p = subprocess.run(ps, capture_output=True, text=False, timeout=20)
        out = (p.stdout or b"").decode("utf-8", errors="replace").strip()
        if "|" in out:
            st, sub = out.split("|", 1)
            return st.strip(), sub.strip()
        return "", ""
    except Exception:
        return "", ""


def sha256_of_file(path: str, max_mb: int = 200) -> str:
    """Compute SHA256 of a file (skips very large files)."""
    try:
        size = os.path.getsize(path)
        if size > max_mb * 1024 * 1024:
            return f"(skipped: >{max_mb}MB)"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"(error: {e})"


def file_times(path: str) -> tuple[str, str, datetime.datetime | None]:
    """Return (CreatedStr, ModifiedStr, CreatedDT)."""
    try:
        cts = os.path.getctime(path)
        mts = os.path.getmtime(path)
        cdt = datetime.datetime.fromtimestamp(cts)
        mdt = datetime.datetime.fromtimestamp(mts)
        return cdt.strftime("%Y-%m-%d %H:%M:%S"), mdt.strftime("%Y-%m-%d %H:%M:%S"), cdt
    except Exception:
        return "", "", None


def is_likely_microsoft(company: str, sig_status: str, sig_subject: str, use_authenticode: bool) -> bool:
    """Heuristic check whether a binary is Microsoft-origin."""
    if "microsoft" in (company or "").lower():
        return True
    if use_authenticode:
        if (sig_status or "").lower() == "valid" and "microsoft" in (sig_subject or "").lower():
            return True
    return False


def enumerate_services() -> list[dict]:
    """Enumerate Windows services and return basic descriptors."""
    results = []
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    for name, display, _status in win32service.EnumServicesStatus(scm):
        try:
            hs = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
            cfg = win32service.QueryServiceConfig(hs)
            results.append({"name": name, "display": display, "image_path_raw": cfg[3]})
        except Exception:
            continue
    return results


def export_csv(path: str, records: list[dict]):
    """Export records to CSV."""
    fields = [
        "service_name", "display_name", "binary_path",
        "company", "sig_status", "sig_subject",
        "created", "modified", "sha256",
        "is_new_vs_baseline"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k, "") for k in fields})


def export_json(path: str, records: list[dict]):
    """Export records to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


def load_baseline(path: str) -> dict:
    """Load baseline JSON and return a lookup dict by service_name."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    lookup = {}
    for r in data:
        sn = r.get("service_name")
        if sn:
            lookup[sn] = {"binary_path": r.get("binary_path")}
    return lookup


def mark_new_vs_baseline(records: list[dict], baseline_lookup: dict) -> int:
    """Mark records that are not present in baseline (by service name)."""
    new_count = 0
    for r in records:
        sn = r.get("service_name")
        if sn not in baseline_lookup:
            r["is_new_vs_baseline"] = True
            new_count += 1
        else:
            r["is_new_vs_baseline"] = False
    return new_count


def open_in_explorer(path: str):
    """Open File Explorer and select the given file."""
    if path and os.path.exists(path):
        subprocess.run(["explorer.exe", "/select,", path], shell=False)


class App(tk.Tk):
    """Tkinter GUI for auditing Windows services (non-Microsoft candidates)."""
    def __init__(self):
        super().__init__()
        self.title("Non-Microsoft Windows Services Audit")
        self.geometry("1250x700")
        self.minsize(1050, 600)

        self.records: list[dict] = []
        self.baseline_lookup: dict | None = None

        self._scan_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._ui_queue: "queue.Queue[tuple]" = queue.Queue()

        self._build_ui()
        self.after(80, self._drain_queue)

    def _build_ui(self):
        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)

        top = ttk.Frame(root)
        top.pack(fill="x")

        self.var_auth = tk.BooleanVar(value=True)
        self.var_hash = tk.BooleanVar(value=False)
        self.var_only_new = tk.BooleanVar(value=False)
        self.var_since = tk.StringVar(value="")
        self.var_status = tk.StringVar(value="Idle.")

        cb_auth = ttk.Checkbutton(top, text="Validate signature via Authenticode (slower)", variable=self.var_auth)
        cb_hash = ttk.Checkbutton(top, text="Compute SHA256 for binaries", variable=self.var_hash)
        cb_only_new = ttk.Checkbutton(top, text="Show only NEW vs baseline", variable=self.var_only_new)

        cb_auth.grid(row=0, column=0, sticky="w", padx=(0, 14))
        cb_hash.grid(row=0, column=1, sticky="w", padx=(0, 14))
        cb_only_new.grid(row=0, column=2, sticky="w", padx=(0, 14))

        Tooltip(cb_auth,
                "Uses PowerShell Get-AuthenticodeSignature to check if the file is signed by Microsoft.\n"
                "More accurate, but noticeably slower.")
        Tooltip(cb_hash,
                "Computes SHA256 for each service executable.\n"
                "Useful for incident response and baselining, but slower on many services.")
        Tooltip(cb_only_new,
                "If a baseline is loaded, show only services that are not present in that baseline.")

        since_lbl = ttk.Label(top, text="Only include files created on/after (YYYY-MM-DD):")
        since_ent = ttk.Entry(top, textvariable=self.var_since, width=14)
        since_lbl.grid(row=1, column=0, sticky="w", pady=(8, 0))
        since_ent.grid(row=1, column=1, sticky="w", pady=(8, 0))
        Tooltip(since_ent,
                "Filters by file creation time (local time). This is an approximation of install time.\n"
                "Leave empty to disable the filter.")

        btns = ttk.Frame(top)
        btns.grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))

        self.btn_scan = ttk.Button(btns, text="Scan", command=self.on_scan)
        self.btn_stop = ttk.Button(btns, text="Stop", command=self.on_stop, state="disabled")
        self.btn_save_base = ttk.Button(btns, text="Save Baseline", command=self.on_save_baseline)
        self.btn_load_base = ttk.Button(btns, text="Load Baseline & Compare", command=self.on_load_baseline)
        self.btn_export_csv = ttk.Button(btns, text="Export CSV", command=self.on_export_csv)
        self.btn_export_json = ttk.Button(btns, text="Export JSON", command=self.on_export_json)

        self.btn_scan.grid(row=0, column=0, padx=(0, 10))
        self.btn_stop.grid(row=0, column=1, padx=(0, 10))
        self.btn_save_base.grid(row=0, column=2, padx=(0, 10))
        self.btn_load_base.grid(row=0, column=3, padx=(0, 10))
        self.btn_export_csv.grid(row=0, column=4, padx=(0, 10))
        self.btn_export_json.grid(row=0, column=5, padx=(0, 10))

        Tooltip(self.btn_scan, "Run the scan and list non-Microsoft service candidates.")
        Tooltip(self.btn_stop, "Abort the scan. Partial results will remain visible.")
        Tooltip(self.btn_save_base, "Save the current result list as a baseline JSON file.")
        Tooltip(self.btn_load_base, "Load a baseline JSON and mark entries that are new since that baseline.")
        Tooltip(self.btn_export_csv, "Export the currently displayed records to CSV.")
        Tooltip(self.btn_export_json, "Export the currently displayed records to JSON.")

        prog_frame = ttk.Frame(root)
        prog_frame.pack(fill="x", pady=(10, 0))
        self.prog = ttk.Progressbar(prog_frame, mode="determinate")
        self.prog.pack(fill="x")
        Tooltip(self.prog, "Progress of the current scan.")

        sep = ttk.Separator(root)
        sep.pack(fill="x", pady=10)

        table_frame = ttk.Frame(root)
        table_frame.pack(fill="both", expand=True)

        cols = (
            "new", "service_name", "display_name", "binary_path",
            "company", "sig_status", "created", "modified", "sha256"
        )

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        headers = {
            "new": "NEW",
            "service_name": "Service Name",
            "display_name": "Display Name",
            "binary_path": "Binary Path",
            "company": "Company",
            "sig_status": "Sig Status",
            "created": "Created",
            "modified": "Modified",
            "sha256": "SHA256",
        }
        for c in cols:
            self.tree.heading(c, text=headers[c])

        self.tree.column("new", width=55, anchor="center")
        self.tree.column("service_name", width=170)
        self.tree.column("display_name", width=240)
        self.tree.column("binary_path", width=460)
        self.tree.column("company", width=220)
        self.tree.column("sig_status", width=110)
        self.tree.column("created", width=140)
        self.tree.column("modified", width=140)
        self.tree.column("sha256", width=380)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self.on_double_click)

        bottom = ttk.Frame(root)
        bottom.pack(fill="x", pady=(8, 0))
        self.status = ttk.Label(bottom, textvariable=self.var_status)
        self.status.pack(side="left")

    def set_busy(self, busy: bool):
        """Enable/disable UI buttons during scanning."""
        if busy:
            self.btn_scan.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            for b in (self.btn_save_base, self.btn_load_base, self.btn_export_csv, self.btn_export_json):
                b.configure(state="disabled")
        else:
            self.btn_scan.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            for b in (self.btn_save_base, self.btn_load_base, self.btn_export_csv, self.btn_export_json):
                b.configure(state="normal")
        self.update_idletasks()

    def parse_since_date(self) -> datetime.datetime | None:
        """Parse YYYY-MM-DD filter input."""
        s = self.var_since.get().strip()
        if not s:
            return None
        try:
            return datetime.datetime.strptime(s, "%Y-%m-%d")
        except Exception:
            messagebox.showerror("Invalid date", "Please use YYYY-MM-DD or leave empty.")
            return None

    def refresh_table(self):
        """Re-render Treeview according to current records and filters."""
        self.tree.delete(*self.tree.get_children())
        show_only_new = self.var_only_new.get() and (self.baseline_lookup is not None)
        for r in self.records:
            if show_only_new and not r.get("is_new_vs_baseline"):
                continue
            new_flag = "YES" if r.get("is_new_vs_baseline") else ""
            self.tree.insert(
                "",
                "end",
                values=(
                    new_flag,
                    r.get("service_name", ""),
                    r.get("display_name", ""),
                    r.get("binary_path", ""),
                    r.get("company", ""),
                    r.get("sig_status", ""),
                    r.get("created", ""),
                    r.get("modified", ""),
                    r.get("sha256", ""),
                ),
            )

    def on_double_click(self, _event=None):
        """Open selected binary in Explorer on double click."""
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        values = item.get("values", [])
        if len(values) >= 4:
            open_in_explorer(values[3])

    def on_stop(self):
        """Signal the worker thread to stop."""
        if self._scan_thread and self._scan_thread.is_alive():
            self._stop_event.set()
            self.var_status.set("Stop requested... waiting for current item to finish.")

    def on_scan(self):
        """Start scan in background thread."""
        if self._scan_thread and self._scan_thread.is_alive():
            return

        since_dt = self.parse_since_date()
        if self.var_since.get().strip() and since_dt is None:
            return

        use_auth = bool(self.var_auth.get())
        include_hash = bool(self.var_hash.get())

        self._stop_event.clear()
        self.set_busy(True)
        self.records = []
        self.refresh_table()

        raw = enumerate_services()
        total = len(raw)
        self.prog.configure(maximum=max(total, 1), value=0)
        self.var_status.set(f"Starting scan... (0/{total})")

        def worker():
            t0 = time.time()
            found = 0
            for idx, svc in enumerate(raw, start=1):
                if self._stop_event.is_set():
                    break

                name = svc["name"]
                self._ui_queue.put(("status", f"Scanning {idx}/{total}: {name}"))
                self._ui_queue.put(("progress", idx))

                exe = parse_service_image_path(svc.get("image_path_raw", ""))
                if not exe or not os.path.exists(exe):
                    continue

                created_s, modified_s, created_dt = file_times(exe)
                if since_dt and created_dt and created_dt < since_dt:
                    continue

                company = get_file_company_name(exe)

                sig_status, sig_subject = ("", "")
                if use_auth:
                    sig_status, sig_subject = authenticode_signer_subject(exe)

                if is_likely_microsoft(company, sig_status, sig_subject, use_auth):
                    continue

                h = sha256_of_file(exe) if include_hash else ""

                rec = {
                    "service_name": name,
                    "display_name": svc["display"],
                    "binary_path": exe,
                    "company": company,
                    "sig_status": sig_status,
                    "sig_subject": sig_subject,
                    "created": created_s,
                    "modified": modified_s,
                    "sha256": h,
                    "is_new_vs_baseline": False,
                }
                found += 1
                self._ui_queue.put(("append_record", rec))

            # finalize
            elapsed = time.time() - t0
            self._ui_queue.put(("finalize", {"elapsed": elapsed}))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _drain_queue(self):
        """Process UI updates from the worker thread."""
        try:
            while True:
                msg = self._ui_queue.get_nowait()
                kind = msg[0]

                if kind == "status":
                    self.var_status.set(msg[1])

                elif kind == "progress":
                    self.prog.configure(value=msg[1])

                elif kind == "append_record":
                    rec = msg[1]
                    # baseline compare can be applied live as well
                    if self.baseline_lookup is not None:
                        rec["is_new_vs_baseline"] = rec["service_name"] not in self.baseline_lookup
                    self.records.append(rec)
                    # update table incrementally for "live" results
                    self.refresh_table()

                elif kind == "finalize":
                    info = msg[1]
                    if self.baseline_lookup is not None:
                        new_count = mark_new_vs_baseline(self.records, self.baseline_lookup)
                        base_note = f" New vs baseline: {new_count}."
                    else:
                        base_note = ""

                    stopped = self._stop_event.is_set()
                    stop_note = " (stopped)" if stopped else ""
                    self.var_status.set(
                        f"Scan done{stop_note}. Found {len(self.records)} candidates.{base_note} "
                        f"(Elapsed: {info['elapsed']:.1f}s)"
                    )
                    self.set_busy(False)

        except queue.Empty:
            pass

        self.after(80, self._drain_queue)

    def current_displayed_records(self) -> list[dict]:
        """Return records currently visible, respecting 'show only new' filter."""
        show_only_new = self.var_only_new.get() and (self.baseline_lookup is not None)
        if not show_only_new:
            return self.records[:]
        return [r for r in self.records if r.get("is_new_vs_baseline")]

    def on_save_baseline(self):
        """Save current records as baseline JSON."""
        if not self.records:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save baseline JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )
        if not path:
            return
        export_json(path, self.records)
        messagebox.showinfo("Baseline saved", f"Baseline saved to:\n{path}")

    def on_load_baseline(self):
        """Load baseline JSON and compare."""
        path = filedialog.askopenfilename(
            title="Load baseline JSON",
            filetypes=[("JSON files", "*.json")],
        )
        if not path:
            return
        try:
            self.baseline_lookup = load_baseline(path)
        except Exception as e:
            messagebox.showerror("Failed to load baseline", str(e))
            return

        if self.records:
            new_count = mark_new_vs_baseline(self.records, self.baseline_lookup)
            self.refresh_table()
            self.var_status.set(f"Baseline loaded. New vs baseline in current list: {new_count}.")
        else:
            self.var_status.set("Baseline loaded. Run a scan to compare.")

    def on_export_csv(self):
        """Export displayed records to CSV."""
        data = self.current_displayed_records()
        if not data:
            messagebox.showwarning("No data", "Nothing to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if not path:
            return
        export_csv(path, data)
        messagebox.showinfo("Export complete", f"CSV exported to:\n{path}")

    def on_export_json(self):
        """Export displayed records to JSON."""
        data = self.current_displayed_records()
        if not data:
            messagebox.showwarning("No data", "Nothing to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )
        if not path:
            return
        export_json(path, data)
        messagebox.showinfo("Export complete", f"JSON exported to:\n{path}")


if __name__ == "__main__":
    App().mainloop()
