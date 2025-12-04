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


# ==================== SCRIPT INFO ====================
# Map of script labels to their Python file paths
SCRIPT_PATHS = {
    'chrome_downloads': 'Browser Data/Chrome/Chrome_Downloads.py',
    'chrome_history': 'Browser Data/Chrome/Chrome_History.py',
    'chrome_extensions': 'Browser Data/Chrome/Chrome_Extensions.py',
    'chrome_sessions': 'Browser Data/Chrome/Chrome_Sessions.py',
    'chrome_autofill': 'Browser Data/Chrome/Chrome_Autofill.py',
    'chrome_decrypt': 'Browser Data/Chrome/chrome_decrypt.py',
    'firefox_downloads': 'Browser Data/Firefox/Firefox_Downloads.py',
    'firefox_history': 'Browser Data/Firefox/Firefox_History.py',
    'firefox_extensions': 'Browser Data/Firefox/Firefox_Extensions.py',
    'firefox_sessions': 'Browser Data/Firefox/Firefox_Sessions.py',
}


class ScriptRunnerDialog(tk.Toplevel):
    """Dialog for selecting and running individual scripts with argument configuration."""

    def __init__(self, parent, log_callback, clear_log, runner_holder):
        super().__init__(parent)
        self.title('Run Script')
        self.geometry('900x600')
        self.transient(parent)

        self.log_callback = log_callback
        self.clear_log = clear_log
        self.runner_holder = runner_holder  # to store runner and check if running

        self.selected_script = tk.StringVar()
        self.custom_args = tk.StringVar()

        self._build_ui()
        self._populate_scripts()

    def _build_ui(self):
        # Main paned window: left = script list, right = help + args
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # LEFT: Script list
        left_frame = ttk.Frame(paned, width=200)
        paned.add(left_frame, weight=1)

        ttk.Label(left_frame, text='Available Scripts:').pack(anchor=tk.W)
        self.script_listbox = tk.Listbox(left_frame, exportselection=False)
        self.script_listbox.pack(fill=tk.BOTH, expand=True, pady=4)
        self.script_listbox.bind('<<ListboxSelect>>', self._on_script_select)

        # RIGHT: Help display + arguments
        right_frame = ttk.Frame(paned, width=600)
        paned.add(right_frame, weight=3)

        # Help text area
        help_label_frame = ttk.LabelFrame(right_frame, text='Script Help (--help)')
        help_label_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        self.help_text = tk.Text(help_label_frame, height=15, wrap='word', state='disabled',
                                  font=('Consolas', 9), bg='#f5f5f5')
        self.help_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        help_scroll = ttk.Scrollbar(help_label_frame, command=self.help_text.yview)
        self.help_text.configure(yscrollcommand=help_scroll.set)
        help_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Arguments section
        args_frame = ttk.LabelFrame(right_frame, text='Arguments')
        args_frame.pack(fill=tk.X, pady=4)

        # Common checkboxes (will be dynamically populated based on script)
        self.checkbox_frame = ttk.Frame(args_frame)
        self.checkbox_frame.pack(fill=tk.X, padx=4, pady=4)
        self.arg_checkboxes = {}  # {arg_name: BooleanVar}

        # Custom args entry
        custom_frame = ttk.Frame(args_frame)
        custom_frame.pack(fill=tk.X, padx=4, pady=4)
        ttk.Label(custom_frame, text='Custom arguments:').pack(side=tk.LEFT)
        ttk.Entry(custom_frame, textvariable=self.custom_args, width=50).pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)

        # Output file option
        output_frame = ttk.Frame(args_frame)
        output_frame.pack(fill=tk.X, padx=4, pady=4)
        self.output_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(output_frame, text='--output', variable=self.output_enabled).pack(side=tk.LEFT)
        self.output_path = tk.StringVar()
        self.output_entry = ttk.Entry(output_frame, textvariable=self.output_path, width=40)
        self.output_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(output_frame, text='Browse...', command=self._browse_output).pack(side=tk.LEFT)

        # Run button
        btn_frame = ttk.Frame(right_frame)
        btn_frame.pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text='Run Script', command=self._run_script).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Close', command=self.destroy).pack(side=tk.RIGHT, padx=4)

    def _populate_scripts(self):
        """Populate the script listbox."""
        self.script_listbox.delete(0, 'end')
        for label in sorted(SCRIPT_PATHS.keys()):
            self.script_listbox.insert('end', label)

    def _on_script_select(self, event):
        """Handle script selection — fetch and display --help."""
        sel = self.script_listbox.curselection()
        if not sel:
            return
        label = self.script_listbox.get(sel[0])
        self.selected_script.set(label)

        script_path = SCRIPT_PATHS.get(label)
        if not script_path:
            self._show_help('(Script path not found)')
            return

        full_path = ROOT_DIR / script_path
        if not full_path.exists():
            self._show_help(f'(Script not found: {full_path})')
            return

        # Fetch --help output
        self._show_help('Loading help...')
        self.update_idletasks()

        try:
            result = subprocess.run(
                [sys.executable, str(full_path), '--help'],
                capture_output=True, text=True, timeout=10, cwd=str(ROOT_DIR)
            )
            help_text = result.stdout or result.stderr or '(No help available)'
            self._show_help(help_text)
            self._parse_and_create_checkboxes(help_text)
        except subprocess.TimeoutExpired:
            self._show_help('(Timed out fetching help)')
        except Exception as e:
            self._show_help(f'(Error: {e})')

    def _show_help(self, text: str):
        """Display help text in the text widget."""
        self.help_text.configure(state='normal')
        self.help_text.delete('1.0', 'end')
        self.help_text.insert('1.0', text)
        self.help_text.configure(state='disabled')

    def _parse_and_create_checkboxes(self, help_text: str):
        """Parse help text and create checkboxes for boolean flags."""
        # Clear existing checkboxes
        for widget in self.checkbox_frame.winfo_children():
            widget.destroy()
        self.arg_checkboxes.clear()

        # Parse flags from help text (look for --flag patterns without required values)
        import re
        # Match flags that appear to be boolean (no uppercase PLACEHOLDER after them)
        # e.g., --debug, --full-report, --include-cookie-only
        lines = help_text.split('\n')
        flags_found = []

        for line in lines:
            # Look for --flag patterns
            matches = re.findall(r'(--[\w-]+)(?:\s|$|,)', line)
            for match in matches:
                flag = match
                # Skip flags that seem to require values (followed by uppercase word or specific patterns)
                if flag in ['--help', '-h', '--output', '--days', '--profile', '--session-timeout']:
                    continue
                # Check if this line suggests the flag takes a value
                if re.search(rf'{re.escape(flag)}\s+[A-Z_]+', line):
                    continue
                if flag not in flags_found:
                    flags_found.append(flag)

        # Create checkboxes in a grid
        col = 0
        row = 0
        max_cols = 3
        for flag in flags_found:
            var = tk.BooleanVar(value=False)
            self.arg_checkboxes[flag] = var
            cb = ttk.Checkbutton(self.checkbox_frame, text=flag, variable=var)
            cb.grid(row=row, column=col, sticky=tk.W, padx=4, pady=2)
            col += 1
            if col >= max_cols:
                col = 0
                row += 1

        if not flags_found:
            ttk.Label(self.checkbox_frame, text='(No boolean flags detected)').grid(row=0, column=0)

    def _browse_output(self):
        """Browse for output file path."""
        fp = filedialog.asksaveasfilename(
            initialdir=str(OUTPUTS_DIR),
            title='Select output file',
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')]
        )
        if fp:
            self.output_path.set(fp)
            self.output_enabled.set(True)

    def _run_script(self):
        """Build command and run the selected script."""
        label = self.selected_script.get()
        if not label:
            messagebox.showwarning('No script', 'Select a script first.')
            return

        script_path = SCRIPT_PATHS.get(label)
        if not script_path:
            messagebox.showerror('Error', f'Script path not found for: {label}')
            return

        full_path = ROOT_DIR / script_path
        if not full_path.exists():
            messagebox.showerror('Error', f'Script not found: {full_path}')
            return

        # Check if a run is already in progress
        if self.runner_holder.runner and self.runner_holder.runner.is_alive():
            messagebox.showwarning('Already running', 'A script is already running. Stop it first.')
            return

        # Build command
        cmd = [sys.executable, str(full_path)]

        # Add checked flags
        for flag, var in self.arg_checkboxes.items():
            if var.get():
                cmd.append(flag)

        # Add output if enabled
        if self.output_enabled.get() and self.output_path.get().strip():
            cmd.extend(['--output', self.output_path.get().strip()])

        # Add custom args
        custom = self.custom_args.get().strip()
        if custom:
            cmd.extend(custom.split())

        # Run the script
        self.clear_log()
        self.log_callback(f'Running: {" ".join(cmd)}\n')
        self.runner_holder.runner = RunnerThread(
            cmd, cwd=str(ROOT_DIR),
            log_callback=self.log_callback,
            done_callback=self._on_run_done
        )
        self.runner_holder.runner.start()

    def _on_run_done(self, rc):
        """Called when script finishes."""
        self.log_callback(f'\nScript finished with return code: {rc}\n')


class RunAllGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Browser Forensics — Run All GUI')
        self.geometry('1000x700')

        self.debug_mode = tk.BooleanVar(value=False)
        self.html_report = tk.BooleanVar(value=True)
        self.no_passwords = tk.BooleanVar(value=False)
        self.no_addresses = tk.BooleanVar(value=False)
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
        ttk.Checkbutton(top_frame, text='No addresses in HTML', variable=self.no_addresses).grid(row=1, column=3, sticky=tk.W)
        ttk.Checkbutton(top_frame, text='Filter token', variable=self.filter_token).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(top_frame, text='Filter suspicious', variable=self.filter_suspicious).grid(row=2, column=1, sticky=tk.W)

        ttk.Label(top_frame, text='Include scripts (comma list):').grid(row=3, column=0, sticky=tk.W, pady=4)
        ttk.Entry(top_frame, textvariable=self.include_list, width=50).grid(row=3, column=1, pady=4, sticky=tk.W)
        ttk.Label(top_frame, text='Exclude scripts (comma list):').grid(row=4, column=0, sticky=tk.W)
        ttk.Entry(top_frame, textvariable=self.exclude_list, width=50).grid(row=4, column=1, sticky=tk.W)

        ttk.Label(top_frame, text='Only (chrome/firefox/all):').grid(row=5, column=0, sticky=tk.W)
        ttk.Combobox(top_frame, values=['all', 'chrome', 'firefox'], textvariable=self.only_mode, state='readonly', width=12).grid(row=5, column=1, sticky=tk.W)

        ttk.Label(top_frame, text='Additional args:').grid(row=6, column=0, sticky=tk.W, pady=4)
        ttk.Entry(top_frame, textvariable=self.additional_args, width=50).grid(row=6, column=1, sticky=tk.W)

        btn_frame = ttk.Frame(top_frame)
        btn_frame.grid(row=7, column=0, columnspan=3, pady=6)
        ttk.Button(btn_frame, text='Run All', command=self._do_run_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Stop', command=self._stop_run).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Show Outputs Folder', command=self._show_output_folder).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Run Script...', command=self._open_script_runner).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Open Last Report', command=self._open_last_report).pack(side=tk.LEFT, padx=4)

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

        # ==================== FILE BROWSER + CSV PREVIEW ====================
        viewer_frame = ttk.Frame(self)
        viewer_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=6)

        # LEFT PANEL: Hierarchical file tree + action buttons
        left_v = ttk.Frame(viewer_frame, width=280)
        left_v.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        left_v.pack_propagate(False)

        ttk.Label(left_v, text='Output Files (folders → files):').pack(anchor=tk.W)

        # Single Treeview for folders and files
        tree_frame = ttk.Frame(left_v)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        self.file_tree = ttk.Treeview(tree_frame, show='tree', selectmode='browse')
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind selection and double-click
        self.file_tree.bind('<<TreeviewSelect>>', self._on_file_tree_select)
        self.file_tree.bind('<Double-1>', self._on_file_tree_double_click)

        # Action buttons
        btn_frame = ttk.Frame(left_v)
        btn_frame.pack(fill=tk.X, pady=4)
        ttk.Button(btn_frame, text='Refresh', command=self._populate_file_tree).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text='Preview', command=self._preview_selected_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text='Open', command=self._open_selected_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text='Folder', command=self._show_output_folder).pack(side=tk.LEFT, padx=2)

        # Selected file path display
        self.file_path_var = tk.StringVar()
        path_frame = ttk.LabelFrame(left_v, text='Selected File')
        path_frame.pack(fill=tk.X, pady=4)
        path_entry = ttk.Entry(path_frame, textvariable=self.file_path_var, state='readonly')
        path_entry.pack(fill=tk.X, padx=4, pady=4)

        # RIGHT PANEL: CSV Preview Treeview
        right_v = ttk.Frame(viewer_frame)
        right_v.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right_v, text='CSV Preview (first {} rows):'.format(CSV_PREVIEW_ROWS)).pack(anchor=tk.W)

        preview_frame = ttk.Frame(right_v)
        preview_frame.pack(fill=tk.BOTH, expand=True)
        self.preview_tree = ttk.Treeview(preview_frame)
        self.preview_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        preview_vscroll = ttk.Scrollbar(preview_frame, orient='vertical', command=self.preview_tree.yview)
        self.preview_tree.configure(yscrollcommand=preview_vscroll.set)
        preview_vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        preview_hscroll = ttk.Scrollbar(right_v, orient='horizontal', command=self.preview_tree.xview)
        self.preview_tree.configure(xscrollcommand=preview_hscroll.set)
        preview_hscroll.pack(fill=tk.X)

        # ==================== END FILE BROWSER ====================

        # initial population
        self._populate_file_tree()

    def _open_script_runner(self):
        """Open the script runner dialog."""
        ScriptRunnerDialog(self, log_callback=self._log, clear_log=self._clear_log, runner_holder=self)

    def _browse_output_dir(self):
        val = filedialog.askdirectory(initialdir=str(OUTPUTS_DIR), title='Select outputs dir')
        if val:
            self.last_outdir.set(val)
            self._populate_file_tree()

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
        if self.no_addresses.get():
            cmd.append('--no-addresses')
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
            self._populate_file_tree()
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
        self._populate_file_tree()

    # ==================== FILE TREE METHODS ====================

    def _populate_file_tree(self):
        """Populate the file tree with timestamp folders and their contents."""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        base_path = Path(self.last_outdir.get() or str(OUTPUTS_DIR))
        if not base_path.exists():
            return

        # Get timestamp folders sorted by name (most recent first)
        folders = sorted([d for d in base_path.iterdir() if d.is_dir()], key=lambda p: p.name, reverse=True)

        for folder in folders:
            # Insert folder as a parent node
            folder_id = self.file_tree.insert('', 'end', text=f'📁 {folder.name}', values=(str(folder),), open=False)

            # Add files inside the folder
            files = sorted(folder.iterdir(), key=lambda p: p.name)
            for f in files:
                if f.is_file():
                    icon = '📄' if f.suffix.lower() == '.csv' else '🌐' if f.suffix.lower() == '.html' else '📝'
                    self.file_tree.insert(folder_id, 'end', text=f'{icon} {f.name}', values=(str(f),))

        # Expand the first (most recent) folder automatically
        if folders:
            first_folder_id = self.file_tree.get_children()[0]
            self.file_tree.item(first_folder_id, open=True)
            # Select the first CSV file if available
            children = self.file_tree.get_children(first_folder_id)
            for child in children:
                item_path = self.file_tree.item(child, 'values')[0]
                if item_path.endswith('.csv'):
                    self.file_tree.selection_set(child)
                    self.file_tree.see(child)
                    self._on_file_tree_select(None)
                    break

    def _on_file_tree_select(self, event):
        """Handle selection in the file tree — update path display and auto-preview CSV."""
        selection = self.file_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.file_tree.item(item, 'values')
        if not values:
            return

        file_path = Path(values[0])
        self.file_path_var.set(str(file_path))

        # Auto-preview if it's a CSV file
        if file_path.is_file() and file_path.suffix.lower() == '.csv':
            self._preview_csv_file(file_path)

    def _on_file_tree_double_click(self, event):
        """Handle double-click — open the selected file externally."""
        selection = self.file_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.file_tree.item(item, 'values')
        if not values:
            return

        file_path = Path(values[0])
        if file_path.is_file():
            self._open_file(file_path)
        elif file_path.is_dir():
            # Toggle folder expansion
            if self.file_tree.item(item, 'open'):
                self.file_tree.item(item, open=False)
            else:
                self.file_tree.item(item, open=True)

    def _preview_selected_file(self):
        """Preview button handler — preview the currently selected file."""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showinfo('No selection', 'Select a file in the tree first.')
            return

        values = self.file_tree.item(selection[0], 'values')
        if not values:
            return

        file_path = Path(values[0])
        if file_path.is_dir():
            messagebox.showinfo('Folder selected', 'Select a file, not a folder.')
            return

        suffix = file_path.suffix.lower()
        if suffix == '.csv':
            self._preview_csv_file(file_path)
        elif suffix == '.html':
            webbrowser.open(str(file_path.resolve()))
        else:
            messagebox.showinfo('Unsupported', f'Preview not supported for {suffix} files. Use Open instead.')

    def _open_selected_file(self):
        """Open button handler — open the currently selected file externally."""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showinfo('No selection', 'Select a file in the tree first.')
            return

        values = self.file_tree.item(selection[0], 'values')
        if not values:
            return

        file_path = Path(values[0])
        if file_path.is_dir():
            try:
                os.startfile(str(file_path))
            except Exception as e:
                messagebox.showerror('Error', f'Could not open folder: {e}')
        else:
            self._open_file(file_path)

    def _preview_csv_file(self, file_path: Path):
        """Load a CSV file into the preview Treeview."""
        if not file_path.exists():
            return
        try:
            with open(file_path, newline='', encoding='utf-8') as fh:
                rdr = csv.DictReader(fh)
                headers = rdr.fieldnames or []
                rows = []
                for i, row in enumerate(rdr):
                    if i >= CSV_PREVIEW_ROWS:
                        break
                    rows.append(row)
            self._display_csv_preview(headers, rows)
        except Exception as e:
            messagebox.showerror('Error', f'Unable to read CSV:\n{e}')

    def _open_file(self, file_path: Path):
        """Open a file with the system default application."""
        try:
            if file_path.suffix.lower() == '.html':
                webbrowser.open(str(file_path.resolve()))
            else:
                os.startfile(str(file_path))
        except Exception as e:
            messagebox.showerror('Error', f'Could not open file:\n{e}')

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

    def _open_last_report(self):
        # Find and open the most recent report.html file
        base_dir = Path(self.last_outdir.get() or OUTPUTS_DIR)
        if not base_dir.exists():
            messagebox.showerror('Missing', f'Output folder does not exist: {base_dir}')
            return
        # List timestamped subdirectories and find the most recent one with report.html
        report_files = []
        for subdir in base_dir.iterdir():
            if subdir.is_dir():
                report_path = subdir / 'report.html'
                if report_path.exists():
                    report_files.append(report_path)
        if not report_files:
            messagebox.showinfo('No Report', 'No report.html files found in any output folder.')
            return
        # Sort by directory name (timestamp) descending to get most recent
        report_files.sort(key=lambda p: p.parent.name, reverse=True)
        latest = report_files[0]
        try:
            webbrowser.open(str(latest))
        except Exception as e:
            messagebox.showerror('Failed', f'Could not open report: {e}')


def main():
    app = RunAllGUI()
    app.mainloop()


if __name__ == '__main__':
    main()
