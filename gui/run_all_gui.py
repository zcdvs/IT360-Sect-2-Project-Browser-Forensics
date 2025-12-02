#!/usr/bin/env python3
"""
A small Tkinter GUI to run the repo's `run_all.py` and view the output CSV/HTML reports.

Features:
- Runs `run_all.py` with common flags (output dir, debug, html report, include/exclude scripts)
- Displays process output (stdout/stderr)
- Lists recent outputs/ timestamped directories created by runs
- Shows CSV previews using a simple Treeview (first N rows)
- Opens the generated HTML report in the default browser

This is intentionally minimal — uses only stdlib modules.
"""

from __future__ import annotations

import os
import sys
import csv
import threading
import subprocess
import webbrowser
import time
from pathlib import Path
try:
    from run_all import SCRIPTS as RUN_ALL_SCRIPTS
except Exception:
    # fallback if import fails
    RUN_ALL_SCRIPTS = []
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

ROOT_DIR = Path(__file__).resolve().parents[1]
RUN_ALL_SCRIPT = ROOT_DIR / 'run_all.py'
OUTPUTS_DIR = ROOT_DIR / 'outputs'

# Default limits
CSV_PREVIEW_ROWS = 500


class RunnerThread(threading.Thread):
    def __init__(self, cmd, cwd, log_callback, done_callback):
        super().__init__(daemon=True)
        self.cmd = cmd
        self.cwd = cwd
        self._stop_event = threading.Event()
        self.log_callback = log_callback
        self.done_callback = done_callback
        self.proc = None

    def run(self):
        try:
            self.proc = subprocess.Popen(self.cmd, cwd=self.cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            self.log_callback(f"Failed to start process: {e}\n")
            self.done_callback(-1)
            return

        # Read lines and forward to GUI
        try:
            for line in self.proc.stdout:
                self.log_callback(line)
                if self._stop_event.is_set():
                    break
            # if we broke out, try to terminate process
            if self._stop_event.is_set():
                try:
                    self.proc.terminate()
                except Exception:
                    pass
                self.done_callback(-1)
                return
            rc = self.proc.wait()
            self.done_callback(rc)
        except Exception as e:
            self.log_callback(f"Error while running process: {e}\n")
            self.done_callback(-1)

    def stop(self):
        self._stop_event.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass


class RunAllGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Browser Forensics — Run All GUI')
        self.geometry('1000x700')

        self.debug_mode = tk.BooleanVar(value=False)
        self.html_report = tk.BooleanVar(value=True)
        self.no_passwords = tk.BooleanVar(value=False)
        self.filter_token = tk.BooleanVar(value=False)
        self.filter_suspicious = tk.BooleanVar(value=False)
        self.include_list = tk.StringVar(value='')
        self.exclude_list = tk.StringVar(value='')
        self.only_mode = tk.StringVar(value='all')
        self.last_outdir = tk.StringVar(value=str(OUTPUTS_DIR))
        self.additional_args = tk.StringVar(value='')

        self.runner = None

        self._build_ui()

    def _build_ui(self):
        top_frame = ttk.Frame(self)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        # Output dir & run controls
        ttk.Label(top_frame, text='Output dir:').grid(row=0, column=0, sticky=tk.W)
        self.outdir_entry = ttk.Entry(top_frame, width=50, textvariable=self.last_outdir)
        self.outdir_entry.grid(row=0, column=1, padx=6, sticky=tk.W)
        ttk.Button(top_frame, text='Browse', command=self._browse_output_dir).grid(row=0, column=2)

        ttk.Checkbutton(top_frame, text='Debug', variable=self.debug_mode).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(top_frame, text='HTML report', variable=self.html_report).grid(row=1, column=1, sticky=tk.W)
        ttk.Checkbutton(top_frame, text='No passwords in HTML', variable=self.no_passwords).grid(row=1, column=2, sticky=tk.W)
        ttk.Checkbutton(top_frame, text='Filter token', variable=self.filter_token).grid(row=1, column=3, sticky=tk.W)
        ttk.Checkbutton(top_frame, text='Filter suspicious', variable=self.filter_suspicious).grid(row=1, column=4, sticky=tk.W)

        ttk.Label(top_frame, text='Include scripts (comma list):').grid(row=2, column=0, sticky=tk.W, pady=4)
        ttk.Entry(top_frame, textvariable=self.include_list, width=50).grid(row=2, column=1, pady=4, sticky=tk.W)
        ttk.Label(top_frame, text='Exclude scripts (comma list):').grid(row=3, column=0, sticky=tk.W)
        ttk.Entry(top_frame, textvariable=self.exclude_list, width=50).grid(row=3, column=1, sticky=tk.W)

        ttk.Label(top_frame, text='Only (chrome/firefox/all):').grid(row=4, column=0, sticky=tk.W)
        ttk.Combobox(top_frame, values=['all', 'chrome', 'firefox'], textvariable=self.only_mode, state='readonly', width=12).grid(row=4, column=1, sticky=tk.W)

        ttk.Label(top_frame, text='Additional args:').grid(row=5, column=0, sticky=tk.W, pady=4)
        ttk.Entry(top_frame, textvariable=self.additional_args, width=50).grid(row=5, column=1, sticky=tk.W)

        btn_frame = ttk.Frame(top_frame)
        btn_frame.grid(row=6, column=0, columnspan=3, pady=6)
        ttk.Button(btn_frame, text='Run All', command=self._do_run_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Stop', command=self._stop_run).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Show Outputs Folder', command=self._show_output_folder).pack(side=tk.LEFT, padx=4)

        # Logs area
        logs_frame = ttk.Frame(self)
        logs_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=False, padx=6, pady=2)
        ttk.Label(logs_frame, text='Process logs:').pack(anchor=tk.W)
        self.log_text = tk.Text(logs_frame, height=12, wrap='none')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        # add vertical scrollbar
        vscroll = ttk.Scrollbar(logs_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)

        # CSV viewer area
        viewer_frame = ttk.Frame(self)
        viewer_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=6)
        left_v = ttk.Frame(viewer_frame)
        left_v.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(left_v, text='Outputs (timestamp folders):').pack(anchor=tk.W)
        self.outputs_listbox = tk.Listbox(left_v, height=10)
        self.outputs_listbox.pack(fill=tk.Y, expand=False)
        self.outputs_listbox.bind('<<ListboxSelect>>', lambda ev: self._refresh_csv_list())
        self.outputs_listbox.bind('<Double-1>', self._on_outputs_double_click)
        ttk.Button(left_v, text='Refresh outputs list', command=self._refresh_outputs).pack(fill=tk.X, pady=2)
        ttk.Button(left_v, text='Open HTML report in browser', command=self._open_report).pack(fill=tk.X, pady=2)

        ttk.Label(left_v, text='CSV files:').pack(anchor=tk.W, pady=(8,0))
        self.csv_listbox = tk.Listbox(left_v, height=12, width=36)
        self.csv_listbox.pack(fill=tk.Y, expand=False)
        self.csv_listbox.bind('<Double-1>', self._on_csv_double_click)
        self.csv_listbox.bind('<<ListboxSelect>>', lambda ev: self._auto_preview_selected_csv())
        ttk.Button(left_v, text='Open CSV in viewer', command=self._open_csv_preview).pack(fill=tk.X)
        ttk.Button(left_v, text='Open CSV in external editor', command=self._open_csv_external).pack(fill=tk.X, pady=2)

        # right side: table preview
        right_v = ttk.Frame(viewer_frame)
        right_v.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right_v, text='CSV Preview (first {} rows):'.format(CSV_PREVIEW_ROWS)).pack(anchor=tk.W)
        self.preview_tree = ttk.Treeview(right_v)
        self.preview_tree.pack(fill=tk.BOTH, expand=True)
        preview_vscroll = ttk.Scrollbar(right_v, command=self.preview_tree.yview)
        self.preview_tree.configure(yscrollcommand=preview_vscroll.set)
        preview_vscroll.pack(side=tk.RIGHT, fill=tk.Y)

        # initial population
        self._refresh_outputs()
        # scripts area
        self._init_scripts_section()

    def _init_scripts_section(self):
        scripts_win = tk.Toplevel(self)
        scripts_win.title('Available scripts')
        scripts_win.geometry('640x260')
        ttk.Label(scripts_win, text='Scripts (select a script then Run Selected Script to execute):').pack(anchor=tk.W, padx=6, pady=4)
        self.scripts_listbox = tk.Listbox(scripts_win, height=8)
        self.scripts_listbox.pack(fill=tk.BOTH, expand=True, padx=6)
        btns = ttk.Frame(scripts_win)
        btns.pack(fill=tk.X, padx=6, pady=6)
        ttk.Button(btns, text='Refresh Scripts', command=self._refresh_scripts_list).pack(side=tk.LEFT)
        self.script_args_var = tk.StringVar()
        ttk.Entry(btns, textvariable=self.script_args_var, width=40).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Run Selected Script', command=self._run_selected_script).pack(side=tk.LEFT)
        self._refresh_scripts_list()

    def _browse_output_dir(self):
        val = filedialog.askdirectory(initialdir=str(OUTPUTS_DIR), title='Select outputs dir')
        if val:
            self.last_outdir.set(val)
            self._refresh_outputs()

    def _log(self, line: str):
        self.log_text.insert('end', line)
        self.log_text.see('end')

    def _clear_log(self):
        self.log_text.delete('1.0', 'end')

    def _do_run_all(self):
        if self.runner and self.runner.is_alive():
            messagebox.showwarning('Already running', 'A run is already in progress. Stop it before starting another.')
            return
        outdir = self.last_outdir.get().strip() or str(OUTPUTS_DIR)
        # build command
        cmd = [sys.executable, str(RUN_ALL_SCRIPT)]
        if self.debug_mode.get():
            cmd.append('--debug')
        cmd.extend(['--outdir', outdir])
        if self.html_report.get():
            cmd.append('--html-report')
        if self.no_passwords.get():
            cmd.append('--no-passwords')
        if self.filter_token.get():
            cmd.append('--filter-token')
        if self.filter_suspicious.get():
            cmd.append('--filter-suspicious')
        inc = self.include_list.get().strip()
        if inc:
            cmd.extend(['--include', inc])
        exc = self.exclude_list.get().strip()
        if exc:
            cmd.extend(['--exclude', exc])
        only = self.only_mode.get().strip()
        if only and only != 'all':
            cmd.extend(['--only', only])
        # additional args
        extra = self.additional_args.get().strip()
        if extra:
            cmd.extend(extra.split())

        self._clear_log()
        self._log('Running: ' + ' '.join(cmd) + '\n')
        self.runner = RunnerThread(cmd, cwd=str(ROOT_DIR), log_callback=self._log, done_callback=self._on_run_done)
        self.runner.start()

        # refresh outputs list after a short delay so the new folder appears when created
        def refresh_later():
            time.sleep(1.5)
            self._refresh_outputs()
        threading.Thread(target=refresh_later, daemon=True).start()

    def _stop_run(self):
        if self.runner and self.runner.is_alive():
            self.runner.stop()
            self._log('Stop requested; waiting for process to shut down...\n')
        else:
            messagebox.showinfo('Not running', 'No run is currently active.')

    def _on_run_done(self, rc):
        self._log(f'Process finished with return code: {rc}\n')
        # refresh outputs list again
        time.sleep(0.5)
        self._refresh_outputs()

    def _refresh_outputs(self):
        path = Path(self.last_outdir.get() or str(OUTPUTS_DIR))
        self.outputs_listbox.delete(0, 'end')
        if not path.exists():
            return
        # list subdirectories, show most recent first
        subdirs = [d for d in path.iterdir() if d.is_dir()]
        subdirs_sorted = sorted(subdirs, key=lambda p: p.name, reverse=True)
        for sd in subdirs_sorted:
            self.outputs_listbox.insert('end', sd.name)
        # select top item if exists
        if subdirs_sorted:
            self.outputs_listbox.select_set(0)
            self._refresh_csv_list()

    def _refresh_csv_list(self):
        # get selected output timestamp folder
        sel = self.outputs_listbox.curselection()
        self.csv_listbox.delete(0, 'end')
        if not sel:
            return
        selected = self.outputs_listbox.get(sel[0])
        folder = Path(self.last_outdir.get()) / selected
        if not folder.exists():
            return
        csvs = sorted([p for p in folder.glob('*.csv')])
        for c in csvs:
            self.csv_listbox.insert('end', c.name)
        # auto select first CSV and preview
        if csvs:
            self.csv_listbox.select_set(0)
            # auto-preview the first CSV in the list
            self._auto_preview_selected_csv()

    def _open_report(self):
        sel = self.outputs_listbox.curselection()
        if not sel:
            messagebox.showerror('No selection', 'Please select an outputs timestamp folder first.')
            return
        selected = self.outputs_listbox.get(sel[0])
        folder = Path(self.last_outdir.get()) / selected
        report = folder / 'report.html'
        if not report.exists():
            messagebox.showerror('Missing', f'No report.html found in {folder}')
            return
        webbrowser.open(str(report.resolve()))

    def _open_csv_preview(self):
        csv_path = self._get_selected_csv_path(show_errors=True)
        if not csv_path:
            return
        if not csv_path.exists():
            messagebox.showerror('Missing', f'{csv_path} not found')
            return
        # load CSV header + rows
        try:
            with open(csv_path, newline='', encoding='utf-8') as fh:
                rdr = csv.DictReader(fh)
                headers = rdr.fieldnames or []
                rows = []
                for i, row in enumerate(rdr):
                    if i >= CSV_PREVIEW_ROWS:
                        break
                    rows.append(row)
        except Exception as e:
            messagebox.showerror('Error', f'Unable to read CSV: {e}')
            return
        # update treeview
        self._display_csv_preview(headers, rows)

    def _display_csv_preview(self, headers, rows):
        # clear
        for col in self.preview_tree.get_children():
            self.preview_tree.delete(col)
        # configure columns explicitly; use '#0' as row index column
        self.preview_tree['columns'] = headers
        self.preview_tree.heading('#0', text='row')
        self.preview_tree.column('#0', width=40, minwidth=40)
        # set headings and widths
        for h in headers:
            try:
                self.preview_tree.heading(h, text=h)
                self.preview_tree.column(h, width=max(80, min(300, len(h) * 10)))
            except Exception:
                # if there is an issue with a header name, fallback to safe string
                safe = str(h)
                self.preview_tree.heading(safe, text=safe)
                self.preview_tree.column(safe, width=120)
            # configure column width heuristically
            self.preview_tree.column(h, width=max(80, min(300, len(h) * 10)))
        for ridx, r in enumerate(rows):
            values = [r.get(h, '') for h in headers]
            self.preview_tree.insert('', 'end', text=str(ridx+1), values=values)

    def _open_csv_external(self):
        csv_path = self._get_selected_csv_path(show_errors=True)
        if not csv_path:
            return
        if not csv_path.exists():
            messagebox.showerror('Missing', f'{csv_path} not found')
            return
        try:
            os.startfile(str(csv_path))
        except Exception as e:
            messagebox.showerror('Open failed', f'Could not open file: {e}')

    def _show_output_folder(self):
        # open the output base folder
        p = Path(self.last_outdir.get() or OUTPUTS_DIR)
        if not p.exists():
            messagebox.showerror('Missing', f'Output folder does not exist: {p}')
            return
        try:
            os.startfile(str(p))
        except Exception as e:
            messagebox.showerror('Failed', f'Could not open folder: {e}')

    def _on_outputs_double_click(self, event):
        # ensure the item under the cursor is selected then open the report
        try:
            idx = self.outputs_listbox.nearest(event.y)
            if idx is None:
                return
            self.outputs_listbox.selection_clear(0, 'end')
            self.outputs_listbox.selection_set(idx)
            self._refresh_csv_list()
            self._open_report()
        except Exception:
            return

    def _on_csv_double_click(self, event):
        try:
            idx = self.csv_listbox.nearest(event.y)
            if idx is None:
                return
            self.csv_listbox.selection_clear(0, 'end')
            self.csv_listbox.selection_set(idx)
            self._auto_preview_selected_csv()
            self._open_csv_preview()
        except Exception:
            return

    def _get_selected_csv_path(self, show_errors: bool = False) -> Path | None:
        sel = self.outputs_listbox.curselection()
        if not sel:
            if show_errors:
                messagebox.showerror('No selection', 'Please select an outputs timestamp folder first.')
            return None
        sel_csv_idx = self.csv_listbox.curselection()
        if not sel_csv_idx:
            if show_errors:
                messagebox.showerror('No CSV', 'Please select a CSV file from the list to preview.')
            return None
        selected = self.outputs_listbox.get(sel[0])
        csv_name = self.csv_listbox.get(sel_csv_idx[0])
        csv_path = Path(self.last_outdir.get()) / selected / csv_name
        if not csv_path.exists():
            if show_errors:
                messagebox.showerror('Missing', f'{csv_path} not found')
            return None
        return csv_path

    def _auto_preview_selected_csv(self):
        csv_path = self._get_selected_csv_path(show_errors=False)
        if not csv_path:
            # nothing selected or no csv
            return
        try:
            with open(csv_path, newline='', encoding='utf-8') as fh:
                rdr = csv.DictReader(fh)
                headers = rdr.fieldnames or []
                rows = []
                for i, row in enumerate(rdr):
                    if i >= CSV_PREVIEW_ROWS:
                        break
                    rows.append(row)
            self._display_csv_preview(headers, rows)
        except Exception:
            # ignore parse errors during auto-preview to avoid annoying popups
            return

    def _refresh_scripts_list(self):
        self.scripts_listbox.delete(0, 'end')
        if RUN_ALL_SCRIPTS:
            for label, cmd in RUN_ALL_SCRIPTS:
                self.scripts_listbox.insert('end', label)
        else:
            # fallback: show common script names
            common = ['chrome_sessions', 'chrome_history', 'chrome_downloads', 'chrome_extensions', 'firefox_sessions', 'firefox_history', 'firefox_downloads', 'firefox_extensions']
            for c in common:
                self.scripts_listbox.insert('end', c)

    def _run_selected_script(self):
        sel = self.scripts_listbox.curselection()
        if not sel:
            messagebox.showerror('No script selected', 'Select a script first.')
            return
        label = self.scripts_listbox.get(sel[0])
        # find command in RUN_ALL_SCRIPTS
        cmd_base = None
        for lab, cb in RUN_ALL_SCRIPTS:
            if lab == label:
                cmd_base = cb.copy()
                break
        if not cmd_base:
            # fallback to building a script path
            cmd_base = [sys.executable, f"Browser Data/Chrome/{label}.py"]
        # allow user to add args
        extra = self.script_args_var.get().strip()
        if extra:
            cmd_base.extend(extra.split())
        self._clear_log()
        self._log('Running: ' + ' '.join(cmd_base) + '\n')
        self.runner = RunnerThread(cmd_base, cwd=str(ROOT_DIR), log_callback=self._log, done_callback=self._on_run_done)
        self.runner.start()


def main():
    app = RunAllGUI()
    app.mainloop()


if __name__ == '__main__':
    main()
