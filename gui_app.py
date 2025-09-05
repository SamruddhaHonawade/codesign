# gui_app.py

import os
import json
import zipfile
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *

# Import from the new, separated cryptographic modules
from hashing import compute_sha3_256
from signing import generate_keypair, sign_digest, verify_signature
from certificate import create_self_signed_cert

# Imports needed for handling crypto objects in the GUI
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class CodeSignerApp(tb.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("🔐Code Signing Tool")
        self.geometry("800x500")
        self.resizable(False, False)

        self.file_path = None
        self.zip_path = None

        self._create_widgets()

    def _create_widgets(self):
        # Notebook (tabs)
        notebook = tb.Notebook(self, bootstyle="primary")
        notebook.pack(fill=BOTH, expand=True, padx=15, pady=15)

        # Sign Tab
        sign_tab = tb.Frame(notebook)
        notebook.add(sign_tab, text="✍️ Sign File")
        self._create_sign_tab(sign_tab)

        # Verify Tab
        verify_tab = tb.Frame(notebook)
        notebook.add(verify_tab, text="🕵️ Verify Package")
        self._create_verify_tab(verify_tab)

        # Log Box
        self.log_box = tk.Text(self, height=8, bg="#1e1e1e", fg="white", insertbackground="white")
        self.log_box.pack(fill=X, padx=15, pady=(0, 10))

    def _create_sign_tab(self, parent):
        self.file_label = tb.Label(parent, text="No file selected", bootstyle="secondary")
        self.file_label.pack(pady=10)
        tb.Button(parent, text="Choose File", bootstyle="primary", command=self.choose_file).pack()

        tb.Label(parent, text="Select Algorithm").pack(pady=(15, 5))
        self.algo_var = tk.StringVar(value="RSA")
        tb.Combobox(parent, textvariable=self.algo_var, values=["RSA", "ECDSA", "Ed25519"], state="readonly").pack()

        tb.Label(parent, text="Publisher Name").pack(pady=(15, 5))
        self.publisher_entry = tb.Entry(parent, width=40)
        self.publisher_entry.insert(0, "My Company Inc.")
        self.publisher_entry.pack()

        tb.Button(parent, text="Sign & Create ZIP", bootstyle="success", command=self.sign_file).pack(pady=20)
        self.sign_status = tb.Label(parent, text="", bootstyle="info")
        self.sign_status.pack()

    def _create_verify_tab(self, parent):
        self.zip_label = tb.Label(parent, text="No package selected", bootstyle="secondary")
        self.zip_label.pack(pady=10)
        tb.Button(parent, text="Choose ZIP", bootstyle="primary", command=self.choose_zip).pack()
        tb.Button(parent, text="Verify", bootstyle="success", command=self.verify_zip).pack(pady=15)
        self.verify_status = tb.Label(parent, text="", bootstyle="warning")
        self.verify_status.pack()

    def log(self, msg):
        self.log_box.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")

    def choose_file(self):
        path = filedialog.askopenfilename(title="Select file to sign")
        if path:
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))
            self.log(f"File selected: {path}")

    def choose_zip(self):
        path = filedialog.askopenfilename(title="Select signed package", filetypes=[("ZIP files", "*.zip")])
        if path:
            self.zip_path = path
            self.zip_label.config(text=os.path.basename(path))
            self.log(f"Package selected: {path}")

    def sign_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "Select a file first.")
            return

        publisher = self.publisher_entry.get()
        if not publisher:
            messagebox.showerror("Error", "Publisher name cannot be empty.")
            return

        try:
            with open(self.file_path, "rb") as f:
                file_bytes = f.read()

            digest = compute_sha3_256(file_bytes)
            algo = self.algo_var.get()

            self.log(f"Generating {algo} keypair...")
            private_key = generate_keypair(algo)

            self.log("Signing digest...")
            sig = sign_digest(private_key, algo, digest)

            self.log("Creating self-signed certificate...")
            cert = create_self_signed_cert(private_key, publisher)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            metadata = {"algorithm": algo, "hash": digest.hex(), "signed_by": publisher}

            outpath = filedialog.asksaveasfilename(
                defaultextension=".zip",
                initialfile=f"signed_{os.path.basename(self.file_path)}.zip",
                filetypes=[("ZIP files", "*.zip")]
            )
            if not outpath: return

            with zipfile.ZipFile(outpath, "w") as z:
                z.writestr(os.path.basename(self.file_path), file_bytes)
                z.writestr("signature.bin", sig)
                z.writestr("certificate.pem", cert_pem)
                z.writestr("metadata.json", json.dumps(metadata, indent=2))

            self.sign_status.config(text="✅ Signed Successfully!", bootstyle="success")
            self.log(f"Signed {self.file_path} -> {outpath}")
        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("Signing Error", str(e))

    def verify_zip(self):
        if not self.zip_path:
            messagebox.showerror("Error", "Select a package first.")
            return

        try:
            with zipfile.ZipFile(self.zip_path, "r") as z:
                filenames = z.namelist()
                required_files = {"signature.bin", "certificate.pem", "metadata.json"}
                if not required_files.issubset(filenames):
                    raise FileNotFoundError("Package is missing required signature files.")

                meta = json.loads(z.read("metadata.json"))
                algo = meta["algorithm"]
                sig = z.read("signature.bin")
                cert_pem = z.read("certificate.pem")
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

                content_file_name = [n for n in filenames if n not in required_files][0]
                file_bytes = z.read(content_file_name)

                self.log(f"Verifying {content_file_name} using {algo}...")
                digest_to_check = compute_sha3_256(file_bytes)

                if digest_to_check.hex() != meta["hash"]:
                    self.verify_status.config(text="❌ HASH MISMATCH - FILE CORRUPTED!", bootstyle="danger")
                    self.log("Verification FAILED: The file's hash does not match the signed hash.")
                    return

                is_valid = verify_signature(cert.public_key(), algo, digest_to_check, sig)

                if is_valid:
                    self.verify_status.config(text=f"✅ Signature VALID (Signed by: {meta['signed_by']})",
                                              bootstyle="success")
                    self.log("Verification SUCCESS: Signature is valid.")
                else:
                    self.verify_status.config(text="❌ Signature INVALID", bootstyle="danger")
                    self.log("Verification FAILED: Signature is invalid.")
        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("Verification Error", str(e))