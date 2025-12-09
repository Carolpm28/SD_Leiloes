import os
import sys
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox

# Ensure project root is on sys.path when executed directly
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

DB_PATH = os.path.join(project_root, 'server.db')


def get_tables(conn):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    return [r[0] for r in cur.fetchall()]


def get_table_info(conn, table):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info('{table}')")
    # returns list of (cid, name, type, notnull, dflt_value, pk)
    return cur.fetchall()


def get_rows(conn, table, limit=500):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM '{table}' LIMIT {limit}")
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    return cols, rows


class DBViewer(tk.Tk):
    def __init__(self, db_path):
        super().__init__()
        self.title(f"DB Viewer - {os.path.basename(db_path)}")
        self.geometry('900x500')
        self.db_path = db_path

        if not os.path.exists(db_path):
            messagebox.showerror("File not found", f"Database file not found: {db_path}")
            self.destroy()
            return

        try:
            self.conn = sqlite3.connect(db_path)
        except Exception as e:
            messagebox.showerror("DB Error", str(e))
            self.destroy()
            return

        self._build_ui()
        self._load_tables()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill='x', padx=8, pady=6)

        ttk.Label(top, text='Table:').pack(side='left')
        self.table_cb = ttk.Combobox(top, state='readonly', width=30)
        self.table_cb.pack(side='left', padx=6)
        self.table_cb.bind('<<ComboboxSelected>>', self.on_table_select)

        ttk.Button(top, text='Refresh', command=self._load_tables).pack(side='left', padx=6)
        ttk.Button(top, text='Reload Rows', command=self.reload_rows).pack(side='left')

        # Treeview for rows
        # Increase row height so rows show more vertical space
        style = ttk.Style()
        try:
            style.configure('Treeview', rowheight=28)
        except Exception:
            pass

        self.tree = ttk.Treeview(self, show='headings')
        self.tree.pack(fill='both', expand=True, padx=8, pady=6)

        # Add a vertical scrollbar
        vsb = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        vsb.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=vsb.set)

        # Info label
        self.info_lbl = ttk.Label(self, text='')
        self.info_lbl.pack(fill='x', padx=8, pady=(0,8))

        # Detail pane: shows full content of selected row (no truncation)
        detail_frame = ttk.LabelFrame(self, text='Row detail (select a row)')
        detail_frame.pack(fill='both', padx=8, pady=(0,8), ipadx=4, ipady=4)

        self.detail_text = tk.Text(detail_frame, height=8, wrap='none')
        self.detail_text.pack(fill='both', expand=True, side='left')

        # Horizontal and vertical scrollbars for detail text
        dt_v = ttk.Scrollbar(detail_frame, orient='vertical', command=self.detail_text.yview)
        dt_v.pack(side='right', fill='y')
        dt_h = ttk.Scrollbar(self, orient='horizontal', command=self.detail_text.xview)
        dt_h.pack(fill='x')
        self.detail_text.configure(yscrollcommand=dt_v.set, xscrollcommand=dt_h.set)

        # Bind selection and double-click
        self.tree.bind('<<TreeviewSelect>>', self.on_row_select)
        self.tree.bind('<Double-1>', self.on_row_double_click)

    def _load_tables(self):
        try:
            tables = get_tables(self.conn)
            self.table_cb['values'] = tables
            if tables:
                # auto-select first table if none selected
                if not self.table_cb.get():
                    self.table_cb.current(0)
                    self.on_table_select()
            else:
                self.table_cb.set('')
                self.clear_tree()
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def on_table_select(self, event=None):
        table = self.table_cb.get()
        if not table:
            return
        self.load_table(table)

    def clear_tree(self):
        for c in self.tree.get_children():
            self.tree.delete(c)
        for h in self.tree['columns']:
            self.tree.heading(h, text='')
        self.tree['columns'] = ()

    def load_table(self, table):
        try:
            cols, rows = get_rows(self.conn, table)
        except Exception as e:
            messagebox.showerror('Query error', str(e))
            return

        # configure columns
        self.tree['columns'] = cols
        for col in cols:
            self.tree.heading(col, text=col)
            # estimate width
            self.tree.column(col, width=max(80, min(300, len(col) * 10)))

        # clear existing
        for r in self.tree.get_children():
            self.tree.delete(r)

        # insert rows, truncating long cell values
        for row in rows:
            display_row = []
            for v in row:
                if v is None:
                    display_row.append('NULL')
                elif isinstance(v, (bytes, bytearray)):
                    # show length and prefix
                    preview = v[:80]
                    try:
                        preview_text = preview.decode('utf-8', errors='ignore')
                    except Exception:
                        preview_text = repr(preview)
                    display_row.append(f"<BLOB {len(v)} bytes> {preview_text}")
                else:
                    s = str(v)
                    if len(s) > 200:
                        s = s[:200] + '...'
                    display_row.append(s)
            self.tree.insert('', 'end', values=display_row)

        # clear detail pane
        self.detail_text.delete('1.0', tk.END)

        self.info_lbl.config(text=f'Table: {table} — showing {len(rows)} row(s) (limit 500)')

    def reload_rows(self):
        table = self.table_cb.get()
        if table:
            self.load_table(table)

    def on_row_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        values = self.tree.item(item, 'values')
        cols = self.tree['columns']
        # Build a detailed multi-line view
        lines = []
        for name, val in zip(cols, values):
            lines.append(f"{name}: {val}")
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, "\n".join(lines))

    def on_row_double_click(self, event=None):
        # Open a popup window with full row content (useful for copy/paste)
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        values = self.tree.item(item, 'values')
        cols = self.tree['columns']
        popup = tk.Toplevel(self)
        popup.title('Row full content')
        text = tk.Text(popup, wrap='none')
        text.pack(fill='both', expand=True)
        vs = ttk.Scrollbar(popup, orient='vertical', command=text.yview)
        vs.pack(side='right', fill='y')
        hs = ttk.Scrollbar(popup, orient='horizontal', command=text.xview)
        hs.pack(fill='x')
        text.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        lines = []
        for name, val in zip(cols, values):
            lines.append(f"{name}: {val}")
        text.insert('1.0', "\n".join(lines))

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.destroy()


def main():
    root = DBViewer(DB_PATH)
    # If DBViewer failed to init it will have called destroy
    try:
        root.mainloop()
    except Exception:
        pass


if __name__ == '__main__':
    main()
