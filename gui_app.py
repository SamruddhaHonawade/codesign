import os
import json
import zipfile
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *

# Import from separated cryptographic modules
from hashing import compute_sha3_256
from signing import generate_keypair, sign_digest, verify_signature
from certificate import create_self_signed_cert

# Imports needed for handling crypto objects in the GUI
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class CodeSignerApp(tb.Window):
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("🔐 Code Signing Tool")
        self.state("zoomed")  # Full screen

        self.file_path = None
        self.zip_path = None
        self.private_key = None
        self.public_key = None
        self.loaded_key_algo = None

        self._create_widgets()

    def _create_widgets(self):
        # Notebook (tabs)
        notebook = tb.Notebook(self, bootstyle="primary")
        notebook.pack(fill=BOTH, expand=True, padx=20, pady=20)

        # Tabs
        sign_tab = tb.Frame(notebook)
        verify_tab = tb.Frame(notebook)
        key_tab = tb.Frame(notebook)

        notebook.add(sign_tab, text="✍️ Sign File")
        notebook.add(verify_tab, text="🕵️ Verify Package")
        notebook.add(key_tab, text="🔑 Key Management")

        self._create_sign_tab(sign_tab)
        self._create_verify_tab(verify_tab)
        self._create_key_tab(key_tab)

        # Log Box
        self.log_box = tk.Text(
            self,
            height=10,
            bg="#1e1e1e",
            fg="white",
            insertbackground="white",
            font=("Consolas", 10)
        )
        self.log_box.pack(fill=X, padx=20, pady=(0, 15))

    # ---------------- SIGN TAB ----------------
    def _create_sign_tab(self, parent):
        frame = tb.Labelframe(parent, text="File Signing", padding=20)
        frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

        self.file_label = tb.Label(frame, text="No file selected", bootstyle="secondary")
        self.file_label.pack(pady=10)
        tb.Button(frame, text="Choose File", bootstyle="primary-outline", command=self.choose_file).pack()

        tb.Label(frame, text="Select Algorithm").pack(pady=(20, 5))
        self.algo_var = tk.StringVar(value="RSA")
        tb.Combobox(frame, textvariable=self.algo_var, values=["RSA", "ECDSA", "Ed25519"], state="readonly").pack()

        tb.Label(frame, text="Publisher Name").pack(pady=(20, 5))
        self.publisher_entry = tb.Entry(frame, width=50)
        self.publisher_entry.insert(0, "My Company Inc.")
        self.publisher_entry.pack()

        tb.Button(frame, text="Sign & Create ZIP", bootstyle="success", command=self.sign_file, width=25).pack(pady=25)
        self.sign_status = tb.Label(frame, text="", bootstyle="info")
        self.sign_status.pack()

    # ---------------- VERIFY TAB ----------------
    def _create_verify_tab(self, parent):
        frame = tb.Labelframe(parent, text="Package Verification", padding=20)
        frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

        self.zip_label = tb.Label(frame, text="No package selected", bootstyle="secondary")
        self.zip_label.pack(pady=10)
        tb.Button(frame, text="Choose ZIP", bootstyle="primary-outline", command=self.choose_zip).pack()

        tb.Button(frame, text="Verify Package", bootstyle="success", command=self.verify_zip, width=25).pack(pady=20)
        self.verify_status = tb.Label(frame, text="", bootstyle="warning")
        self.verify_status.pack()

    # ---------------- KEY MANAGEMENT TAB ----------------
    def _create_key_tab(self, parent):
        frame = tb.Labelframe(parent, text="Manage Keys", padding=20)
        frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

        tb.Label(frame, text="Generate or Load Keys").pack(pady=(0, 15))

        self.key_algo_var = tk.StringVar(value="RSA")
        tb.Combobox(frame, textvariable=self.key_algo_var, values=["RSA", "ECDSA", "Ed25519"], state="readonly").pack(pady=5)

        tb.Button(frame, text="Generate New Keypair", bootstyle="info", command=self.generate_new_key).pack(pady=10)
        tb.Button(frame, text="Load Private Key", bootstyle="primary", command=self.load_private_key).pack(pady=10)
        tb.Button(frame, text="Save Private Key", bootstyle="secondary", command=self.save_private_key).pack(pady=10)

        self.key_status = tb.Label(frame, text="No key loaded", bootstyle="secondary")
        self.key_status.pack(pady=15)

    # ---------------- LOGGING ----------------
    def log(self, msg):
        self.log_box.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")

    # ---------------- FILE SELECTION ----------------
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

    # ---------------- SIGNING ----------------
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

            if not self.private_key:
                self.log(f"Generating {algo} keypair...")
                self.private_key = generate_keypair(algo)
                self.loaded_key_algo = algo

            # Ensure loaded key is used if available
            if self.loaded_key_algo and self.loaded_key_algo != algo:
                self.log(f"Warning: Loaded key is {self.loaded_key_algo}, overriding selection.")
                algo = self.loaded_key_algo

            self.log("Signing digest...")
            sig = sign_digest(self.private_key, algo, digest)

            self.log("Creating self-signed certificate...")
            cert = create_self_signed_cert(self.private_key, publisher)
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

    # ---------------- VERIFY ----------------
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

    # ---------------- KEY MANAGEMENT ----------------
    def generate_new_key(self):
        algo = self.key_algo_var.get()
        self.private_key = generate_keypair(algo)
        self.loaded_key_algo = algo
        self.key_status.config(text=f"✅ New {algo} key generated", bootstyle="success")
        self.log(f"New {algo} keypair generated.")

    def load_private_key(self):
        path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        if path:
            try:
                with open(path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None)
                self.key_status.config(text=f"🔑 Loaded private key from {os.path.basename(path)}", bootstyle="info")
                self.log(f"Private key loaded from {path}")
                # Guess algorithm from key type
                if hasattr(self.private_key, "curve"):
                    self.loaded_key_algo = "ECDSA"
                elif hasattr(self.private_key, "public_key") and "Ed25519" in str(type(self.private_key)):
                    self.loaded_key_algo = "Ed25519"
                else:
                    self.loaded_key_algo = "RSA"
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {e}")

    def save_private_key(self):
        if not self.private_key:
            messagebox.showerror("Error", "No key to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                self.key_status.config(text=f"💾 Key saved to {os.path.basename(path)}", bootstyle="secondary")
                self.log(f"Private key saved to {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {e}")


