"""
des_gui.py — Tkinter GUI for the DES Encryption Demonstrator
================================================================
Project: DES Encryption Demonstrator | Wolanga Jalalzai (AIU24102344) BCS2B
Course : CCS2243 — Cryptography Essential

Two tabs:
  1. "Encrypt / Decrypt" — enter plaintext + 8-byte key (hex), choose ECB or
     CBC, view ciphertext (hex) and round-trip decryption.
  2. "Round-by-Round Trace" — encrypts ONE 64-bit block and displays the
     Initial Permutation output, then L/R, round key, and F-function output
     for all 16 Feistel rounds, and the Final Permutation — i.e. the full
     internal working of DES, satisfying the "Demonstrator" requirement.

Run:  python3 des_gui.py
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

import des


class DesDemonstratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DES Encryption Demonstrator — Wolanga Jalalzai (AIU24102344)")
        self.geometry("880x680")
        self.minsize(760, 560)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.encrypt_tab = EncryptDecryptTab(notebook)
        self.trace_tab = TraceTab(notebook)

        notebook.add(self.encrypt_tab, text="Encrypt / Decrypt")
        notebook.add(self.trace_tab, text="Round-by-Round Trace")


class EncryptDecryptTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=12)

        ttk.Label(self, text="DES Encryption / Decryption",
                  font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        ttk.Label(self, text="Plaintext:").grid(row=1, column=0, sticky="ne", pady=4)
        self.plaintext_box = tk.Text(self, height=4, width=60)
        self.plaintext_box.grid(row=1, column=1, columnspan=2, sticky="we", pady=4)
        self.plaintext_box.insert("1.0", "Attack at dawn!")

        ttk.Label(self, text="Key (16 hex chars / 8 bytes):").grid(row=2, column=0, sticky="e", pady=4)
        self.key_entry = ttk.Entry(self, width=40)
        self.key_entry.grid(row=2, column=1, sticky="w", pady=4)
        self.key_entry.insert(0, "133457799BBCDFF1")
        ttk.Button(self, text="Random Key", command=self.random_key).grid(row=2, column=2, sticky="w", padx=6)

        ttk.Label(self, text="Mode:").grid(row=3, column=0, sticky="e", pady=4)
        self.mode_var = tk.StringVar(value="ECB")
        mode_frame = ttk.Frame(self)
        mode_frame.grid(row=3, column=1, sticky="w")
        ttk.Radiobutton(mode_frame, text="ECB", variable=self.mode_var, value="ECB").pack(side="left")
        ttk.Radiobutton(mode_frame, text="CBC (random IV)", variable=self.mode_var, value="CBC").pack(side="left", padx=10)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(btn_frame, text="Encrypt \u2192", command=self.do_encrypt).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="\u2190 Decrypt", command=self.do_decrypt).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Clear", command=self.clear_all).pack(side="left", padx=6)

        ttk.Label(self, text="Ciphertext (hex):").grid(row=5, column=0, sticky="ne", pady=4)
        self.ciphertext_box = tk.Text(self, height=4, width=60)
        self.ciphertext_box.grid(row=5, column=1, columnspan=2, sticky="we", pady=4)

        ttk.Label(self, text="Recovered plaintext:").grid(row=6, column=0, sticky="ne", pady=4)
        self.recovered_box = tk.Text(self, height=4, width=60, state="normal")
        self.recovered_box.grid(row=6, column=1, columnspan=2, sticky="we", pady=4)

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status_var, foreground="#2a6").grid(
            row=7, column=0, columnspan=3, sticky="w", pady=(8, 0))

        self.columnconfigure(1, weight=1)

    def random_key(self):
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, os.urandom(8).hex().upper())

    def clear_all(self):
        self.plaintext_box.delete("1.0", tk.END)
        self.ciphertext_box.delete("1.0", tk.END)
        self.recovered_box.delete("1.0", tk.END)
        self.status_var.set("Ready.")

    def do_encrypt(self):
        try:
            pt = self.plaintext_box.get("1.0", "end-1c")
            key_hex = self.key_entry.get()
            mode = self.mode_var.get()
            ct_hex = des.encrypt_text(pt, key_hex, mode=mode)
            self.ciphertext_box.delete("1.0", tk.END)
            self.ciphertext_box.insert("1.0", ct_hex.upper())
            self.status_var.set(f"Encrypted successfully with {mode}. "
                                 f"Ciphertext length: {len(ct_hex)//2} bytes.")
        except Exception as e:
            messagebox.showerror("Encryption error", str(e))
            self.status_var.set("Encryption failed — see error dialog.")

    def do_decrypt(self):
        try:
            ct_hex = self.ciphertext_box.get("1.0", "end-1c").strip()
            key_hex = self.key_entry.get()
            mode = self.mode_var.get()
            pt = des.decrypt_text(ct_hex, key_hex, mode=mode)
            self.recovered_box.delete("1.0", tk.END)
            self.recovered_box.insert("1.0", pt)
            self.status_var.set(f"Decrypted successfully with {mode}.")
        except Exception as e:
            messagebox.showerror("Decryption error", str(e))
            self.status_var.set("Decryption failed — see error dialog.")


class TraceTab(ttk.Frame):
    """Shows the full internal state of DES for a single 64-bit block:
    IP output, all 16 rounds (L, R, round key, F output), and FP output."""

    def __init__(self, parent):
        super().__init__(parent, padding=12)

        ttk.Label(self, text="Round-by-Round Internal Trace (single 64-bit block)",
                  font=("Segoe UI", 13, "bold")).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        ttk.Label(self, text="Plaintext block (exactly 8 bytes / 16 hex chars):").grid(row=1, column=0, sticky="e")
        self.block_entry = ttk.Entry(self, width=30)
        self.block_entry.grid(row=1, column=1, sticky="w", padx=6)
        self.block_entry.insert(0, "0123456789ABCDEF")

        ttk.Label(self, text="Key (16 hex chars):").grid(row=1, column=2, sticky="e")
        self.key_entry = ttk.Entry(self, width=24)
        self.key_entry.grid(row=1, column=3, sticky="w", padx=6)
        self.key_entry.insert(0, "133457799BBCDFF1")

        ttk.Button(self, text="Run Trace", command=self.run_trace).grid(row=2, column=0, columnspan=4, pady=8)

        columns = ("round", "L", "R", "round_key", "f_output")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=18)
        headings = {"round": "Round", "L": "L (32 bits)", "R": "R (32 bits)",
                    "round_key": "Round Key Ki (48 bits)", "f_output": "F(R, Ki) (32 bits)"}
        widths = {"round": 55, "L": 130, "R": 130, "round_key": 190, "f_output": 130}
        for c in columns:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="center")
        self.tree.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=6)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=3, column=4, sticky="ns")

        self.summary = scrolledtext.ScrolledText(self, height=6, width=90)
        self.summary.grid(row=4, column=0, columnspan=5, sticky="we", pady=(8, 0))

        self.rowconfigure(3, weight=1)
        for c in range(4):
            self.columnconfigure(c, weight=1)

    def run_trace(self):
        try:
            block_hex = self.block_entry.get().strip()
            key_hex = self.key_entry.get().strip()
            block = bytes.fromhex(block_hex)
            key = bytes.fromhex(key_hex)
            if len(block) != 8:
                raise ValueError("Plaintext block must be exactly 8 bytes (16 hex chars)")
            if len(key) != 8:
                raise ValueError("Key must be exactly 8 bytes (16 hex chars)")

            round_keys = des.generate_round_keys(key)
            trace = des.BlockTrace()
            ct = des.des_encrypt_block(block, round_keys, trace=trace)

            for row in self.tree.get_children():
                self.tree.delete(row)
            for r in trace.rounds:
                self.tree.insert("", "end", values=(
                    r.round_no,
                    self._hex(r.L), self._hex(r.R),
                    self._hex(r.round_key), self._hex(r.f_output)))

            self.summary.delete("1.0", tk.END)
            self.summary.insert(tk.END,
                f"Plaintext (hex)          : {block.hex().upper()}\n"
                f"After Initial Permutation: {self._hex(trace.after_ip)}\n"
                f"Pre-output (R16||L16)    : {self._hex(trace.pre_output_swap)}\n"
                f"Ciphertext (after FP)    : {ct.hex().upper()}\n"
            )
        except Exception as e:
            messagebox.showerror("Trace error", str(e))

    @staticmethod
    def _hex(bitstring: str) -> str:
        """Display a bit-string grouped as hex for readability."""
        val = int(bitstring, 2)
        nibble_count = (len(bitstring) + 3) // 4
        return f"{val:0{nibble_count}X}"


if __name__ == "__main__":
    app = DesDemonstratorApp()
    app.mainloop()
