# gui_app.py

import os
import json
import zipfile
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from pqcrypto.sign.ml_dsa_44 import generate_keypair as ml_dsa_generate_keypair, sign as ml_dsa_sign, verify as ml_dsa_verify

# Import from our backend modules
from signing import generate_keypair, sign_digest
from hashing import compute_sha3_256, compute_sha3_512
from certificate import create_self_signed_cert


# GUI App
class CodeSignerApp(tb.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("🔐Code Signing Tool")
        self.attributes('-fullscreen', True)

        self.file_path = None
        self.zip_path = None
        self.private_key = None
        self.public_key = None
        self.key_path = None

        self._create_widgets()

    def _create_widgets(self):
        notebook = tb.Notebook(self, bootstyle="primary")
        notebook.pack(fill=BOTH, expand=True, padx=15, pady=15)

        key_tab = tb.Frame(notebook)
        notebook.add(key_tab, text="🔑 Key Management")
        self._create_key_tab(key_tab)

        sign_tab = tb.Frame(notebook)
        notebook.add(sign_tab, text="✍️ Sign File")
        self._create_sign_tab(sign_tab)

        verify_tab = tb.Frame(notebook)
        notebook.add(verify_tab, text="🕵️ Verify Package")
        self._create_verify_tab(verify_tab)

        self.log_box = tk.Text(self, height=8, bg="#1e1e1e", fg="white", insertbackground="white")
        self.log_box.pack(fill=X, padx=15, pady=(0, 10))

    def _create_key_tab(self, parent):
        # Key status
        self.key_status = tb.Label(parent, text="No key loaded", bootstyle="warning")
        self.key_status.pack(pady=10)

        # Load existing key
        tb.Button(parent, text="Load Existing Key", bootstyle="primary",
                  command=self.load_key).pack(pady=5)

        # Generate new key section
        tb.Label(parent, text="Generate New Key", font=("Helvetica", 10, "bold")).pack(pady=(20, 5))

        # Algorithm selection
        tb.Label(parent, text="Select Key Algorithm").pack(pady=(5, 5))
        self.algo_var = tk.StringVar(value="RSA")
        tb.Combobox(parent, textvariable=self.algo_var,
                    values=["RSA", "ECDSA", "Ed25519", "ML-DSA-44 (Dilithium - Future Proof)"],
                    state="readonly", width=40).pack()

        # Hashing algorithm selection
        tb.Label(parent, text="Select Hashing Algorithm").pack(pady=(5, 5))
        self.hash_algo_var = tk.StringVar(value="sha3_256 (Fast & Effective)")
        tb.Combobox(parent, textvariable=self.hash_algo_var,
                    values=["sha3_256 (Fast & Effective)", "sha3_512 (Higher Security)"],
                    state="readonly", width=40).pack()

        # Signer details
        details_frame = tb.LabelFrame(parent, text="Signer Details", bootstyle="info")
        details_frame.pack(pady=10, padx=10, fill=X)

        tb.Label(details_frame, text="Country Name (e.g., IN)").pack(anchor=W)
        self.country_entry = tb.Entry(details_frame, width=40)
        self.country_entry.insert(0, "IN")
        self.country_entry.pack(pady=2)

        tb.Label(details_frame, text="State or Province Name (e.g., Karnataka)").pack(anchor=W)
        self.state_entry = tb.Entry(details_frame, width=40)
        self.state_entry.insert(0, "Karnataka")
        self.state_entry.pack(pady=2)

        tb.Label(details_frame, text="Locality Name (e.g., Bengaluru)").pack(anchor=W)
        self.locality_entry = tb.Entry(details_frame, width=40)
        self.locality_entry.insert(0, "Bengaluru")
        self.locality_entry.pack(pady=2)

        tb.Label(details_frame, text="Organization Name (e.g., MyCompany Pvt Ltd)").pack(anchor=W)
        self.org_entry = tb.Entry(details_frame, width=40)
        self.org_entry.insert(0, "MyCompany Pvt Ltd")
        self.org_entry.pack(pady=2)

        tb.Label(details_frame, text="Organizational Unit Name (e.g., Software Division)").pack(anchor=W)
        self.org_unit_entry = tb.Entry(details_frame, width=40)
        self.org_unit_entry.insert(0, "Software Division")
        self.org_unit_entry.pack(pady=2)

        tb.Label(details_frame, text="Common Name (Publisher)").pack(anchor=W)
        self.common_name_entry = tb.Entry(details_frame, width=40)
        self.common_name_entry.insert(0, "My Company Inc.")
        self.common_name_entry.pack(pady=2)

        tb.Label(details_frame, text="Email Address (e.g., support@mycompany.com)").pack(anchor=W)
        self.email_entry = tb.Entry(details_frame, width=40)
        self.email_entry.insert(0, "support@mycompany.com")
        self.email_entry.pack(pady=2)

        tb.Label(details_frame, text="Validity Days (e.g., 365)").pack(anchor=W)
        self.valid_days_entry = tb.Entry(details_frame, width=40)
        self.valid_days_entry.insert(0, "365")
        self.valid_days_entry.pack(pady=2)

        tb.Button(parent, text="Generate Key", bootstyle="success",
                  command=self.generate_key).pack(pady=10)

    def _create_sign_tab(self, parent):
        self.file_label = tb.Label(parent, text="No file selected", bootstyle="secondary")
        self.file_label.pack(pady=10)
        tb.Button(parent, text="Choose File", bootstyle="primary", command=self.choose_file).pack()

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

        # Details display
        self.details_text = scrolledtext.ScrolledText(parent, height=10, wrap=tk.WORD)
        self.details_text.pack(pady=10, fill=BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)

    def log(self, msg):
        self.log_box.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")

    def load_key(self):
        try:
            key_path = filedialog.askopenfilename(
                title="Select private key file",
                filetypes=[("Key files", "*.pem *.key")]
            )
            if not key_path:
                return

            password_str = simpledialog.askstring("Enter Password", "Enter password for the private key (leave blank if none):", show='*')
            if password_str is None:
                return
            password = password_str.encode() if password_str else None

            with open(key_path, "rb") as key_file:
                key_data = key_file.read()

            try:
                self.private_key = serialization.load_pem_private_key(
                    key_data,
                    password=password
                )
                self.public_key = None  # For classical, public from private

                # Detect algorithm
                if isinstance(self.private_key, rsa.RSAPrivateKey):
                    algo = "RSA"
                elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                    algo = "ECDSA"
                elif isinstance(self.private_key, ed25519.Ed25519PrivateKey):
                    algo = "Ed25519"
                else:
                    raise ValueError("Unsupported key type")

            except Exception as e:
                # Assume ML-DSA-44
                self.private_key = key_data
                pub_path = os.path.splitext(key_path)[0] + '.pub'
                if not os.path.exists(pub_path):
                    raise ValueError("Public key file not found.")
                with open(pub_path, "rb") as pub_file:
                    self.public_key = pub_file.read()
                algo = "ML-DSA-44"

            self.algo_var.set(algo if algo != "ML-DSA-44" else "ML-DSA-44 (Dilithium - Future Proof)")

            self.key_path = key_path
            self.key_status.config(text=f"✅ {algo} Key loaded from {os.path.basename(key_path)}", bootstyle="success")
            self.log(f"Private key loaded from {key_path}. Detected algorithm: {algo}")

            # Load signer details if available
            json_path = os.path.splitext(key_path)[0] + '.json'
            if os.path.exists(json_path):
                with open(json_path, 'r') as json_file:
                    details = json.load(json_file)
                    self.country_entry.delete(0, tk.END)
                    self.country_entry.insert(0, details.get('country', 'IN'))
                    self.state_entry.delete(0, tk.END)
                    self.state_entry.insert(0, details.get('state', 'Karnataka'))
                    self.locality_entry.delete(0, tk.END)
                    self.locality_entry.insert(0, details.get('locality', 'Bengaluru'))
                    self.org_entry.delete(0, tk.END)
                    self.org_entry.insert(0, details.get('organization', 'MyCompany Pvt Ltd'))
                    self.org_unit_entry.delete(0, tk.END)
                    self.org_unit_entry.insert(0, details.get('org_unit', 'Software Division'))
                    self.common_name_entry.delete(0, tk.END)
                    self.common_name_entry.insert(0, details.get('common_name', 'My Company Inc.'))
                    self.email_entry.delete(0, tk.END)
                    self.email_entry.insert(0, details.get('email', 'support@mycompany.com'))
                    self.valid_days_entry.delete(0, tk.END)
                    self.valid_days_entry.insert(0, details.get('valid_days', '365'))
                    hash_algo = details.get('hash_algo', 'sha3_256')
                    self.hash_algo_var.set("sha3_256 (Fast & Effective)" if hash_algo == 'sha3_256' else "sha3_512 (Higher Security)")
                self.log(f"Signer details loaded from {json_path}.")
            else:
                self.log("No signer details file found. Using defaults.")

        except Exception as e:
            self.log(f"ERROR loading key: {e}")
            messagebox.showerror("Key Load Error", f"Failed to load key: {str(e)}")

    def generate_key(self):
        try:
            country = self.country_entry.get()
            state = self.state_entry.get()
            locality = self.locality_entry.get()
            org = self.org_entry.get()
            org_unit = self.org_unit_entry.get()
            common_name = self.common_name_entry.get()
            email = self.email_entry.get()
            valid_days_str = self.valid_days_entry.get()
            algo_display = self.algo_var.get()
            hash_algo_display = self.hash_algo_var.get()

            algo = algo_display.split(" ")[0] if "ML-DSA-44" in algo_display else algo_display
            hash_algo = hash_algo_display.split(" ")[0]

            if not all([country, state, locality, org, org_unit, common_name, email, valid_days_str]):
                messagebox.showerror("Error", "All signer details must be filled.")
                return
            if not valid_days_str.isdigit() or int(valid_days_str) <= 0:
                messagebox.showerror("Error", "Validity days must be a positive integer.")
                return

            self.log(f"Generating {algo} keypair...")
            if algo == "ML-DSA-44":
                self.public_key, self.private_key = ml_dsa_generate_keypair()
                password_str = None  # No password for ML-DSA
            else:
                self.private_key = generate_keypair(algo)
                self.public_key = None
                password_str = simpledialog.askstring("Set Password", "Enter password to encrypt the private key (leave blank for none):", show='*')
                if password_str is None:
                    self.key_status.config(text=f"✅ {algo} Key generated (not saved)", bootstyle="success")
                    return

                confirm_str = simpledialog.askstring("Confirm Password", "Confirm password:", show='*')
                if confirm_str is None:
                    self.key_status.config(text=f"✅ {algo} Key generated (not saved)", bootstyle="success")
                    return

                if password_str != confirm_str:
                    messagebox.showerror("Error", "Passwords do not match")
                    return

            if algo != "ML-DSA-44":
                encryption_algorithm = serialization.BestAvailableEncryption(password_str.encode()) if password_str else serialization.NoEncryption()

                pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm
                )

            ext = ".key" if algo == "ML-DSA-44" else ".pem"
            save_path = filedialog.asksaveasfilename(
                defaultextension=ext,
                filetypes=[("Key files", f"*{ext}")],
                title="Save Private Key As"
            )
            if save_path:
                if algo == "ML-DSA-44":
                    with open(save_path, "wb") as f:
                        f.write(self.private_key)
                    with open(save_path + '.pub', "wb") as f:
                        f.write(self.public_key)
                else:
                    with open(save_path, "wb") as f:
                        f.write(pem)
                self.log(f"Private key saved to {save_path}.")
                # Save signer details as JSON
                details = {
                    "country": country,
                    "state": state,
                    "locality": locality,
                    "organization": org,
                    "org_unit": org_unit,
                    "common_name": common_name,
                    "email": email,
                    "valid_days": valid_days_str,
                    "hash_algo": hash_algo,
                    "algo": algo
                }
                json_path = os.path.splitext(save_path)[0] + '.json'
                with open(json_path, "w") as f:
                    json.dump(details, f, indent=2)
                self.log(f"Signer details saved to {json_path}.")
                self.key_path = save_path
                self.key_status.config(text=f"✅ {algo} Key generated and saved to {os.path.basename(save_path)}", bootstyle="success")
            else:
                self.log("Private key not saved by user.")
                self.key_status.config(text=f"✅ {algo} Key generated (not saved)", bootstyle="success")

        except Exception as e:
            self.log(f"ERROR generating key: {e}")
            messagebox.showerror("Key Generation Error", str(e))

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

        if not self.private_key:
            messagebox.showerror("Error", "No private key loaded. Please load or generate a key first.")
            return

        country = self.country_entry.get()
        state = self.state_entry.get()
        locality = self.locality_entry.get()
        org = self.org_entry.get()
        org_unit = self.org_unit_entry.get()
        common_name = self.common_name_entry.get()
        email = self.email_entry.get()
        valid_days_str = self.valid_days_entry.get()
        hash_algo_display = self.hash_algo_var.get()
        algo_display = self.algo_var.get()
        algo = algo_display.split(" ")[0] if "ML-DSA-44" in algo_display else algo_display
        hash_algo = hash_algo_display.split(" ")[0]

        if not all([country, state, locality, org, org_unit, common_name, email, valid_days_str]):
            messagebox.showerror("Error", "All signer details must be filled.")
            return
        if not valid_days_str.isdigit() or int(valid_days_str) <= 0:
            messagebox.showerror("Error", "Validity days must be a positive integer.")
            return

        valid_days = int(valid_days_str)

        try:
            with open(self.file_path, "rb") as f:
                file_bytes = f.read()

            if hash_algo == "sha3_256":
                digest = compute_sha3_256(file_bytes)
            elif hash_algo == "sha3_512":
                digest = compute_sha3_512(file_bytes)
            else:
                raise ValueError("Unsupported hash algorithm")

            self.log("Signing digest...")
            if algo == "ML-DSA-44":
                sig = ml_dsa_sign(self.private_key, digest)
            else:
                sig = sign_digest(self.private_key, algo, digest, hash_algo)

            now = datetime.datetime.utcnow()

            metadata = {
                "algorithm": algo,
                "hash_algorithm": hash_algo,
                "hash": digest.hex(),
                "signed_by": common_name,
                "signed_at": now.isoformat()
            }

            outpath = filedialog.asksaveasfilename(
                defaultextension=".zip",
                initialfile=f"signed_{os.path.basename(self.file_path)}.zip",
                filetypes=[("ZIP files", "*.zip")]
            )
            if not outpath:
                return

            with zipfile.ZipFile(outpath, "w") as z:
                z.writestr(os.path.basename(self.file_path), file_bytes)
                z.writestr("signature.bin", sig)
                z.writestr("metadata.json", json.dumps(metadata, indent=2))
                if algo == "ML-DSA-44":
                    z.writestr("public.key", self.public_key)
                else:
                    self.log("Creating self-signed certificate...")
                    cert = create_self_signed_cert(
                        private_key=self.private_key,
                        country=country,
                        state=state,
                        locality=locality,
                        organization=org,
                        org_unit=org_unit,
                        common_name=common_name,
                        email=email,
                        valid_days=valid_days
                    )
                    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                    z.writestr("certificate.pem", cert_pem)

            self.sign_status.config(text="✅ Signed Successfully!", bootstyle="success")
            self.log(f"Signed {self.file_path} -> {outpath}")

        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("Signing Error", str(e))

    def verify_zip(self):
        if not self.zip_path:
            messagebox.showerror("Error", "Select a package first.")
            return

        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)

        try:
            with zipfile.ZipFile(self.zip_path, "r") as z:
                filenames = z.namelist()
                meta = json.loads(z.read("metadata.json"))
                algo = meta["algorithm"]
                hash_algo = meta.get("hash_algorithm", "sha3_256")
                sig = z.read("signature.bin")

                if algo == "ML-DSA-44":
                    required_files = {"signature.bin", "public.key", "metadata.json"}
                    public_key = z.read("public.key")
                else:
                    required_files = {"signature.bin", "certificate.pem", "metadata.json"}
                    cert_pem = z.read("certificate.pem")
                    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

                if not required_files.issubset(filenames):
                    raise FileNotFoundError("Package is missing required signature files.")

                content_file_name = [n for n in filenames if n not in required_files][0]
                file_bytes = z.read(content_file_name)

                self.log(f"Verifying {content_file_name} using {algo} and {hash_algo}...")

                if hash_algo == "sha3_256":
                    digest_to_check = compute_sha3_256(file_bytes)
                elif hash_algo == "sha3_512":
                    digest_to_check = compute_sha3_512(file_bytes)
                else:
                    raise ValueError("Unsupported hash algorithm")

                if digest_to_check.hex() != meta["hash"]:
                    self.verify_status.config(text="❌ HASH MISMATCH - FILE CORRUPTED!", bootstyle="danger")
                    self.log("Verification FAILED: The file's hash does not match the signed hash.")
                    return

                is_valid = False
                try:
                    if algo == "ML-DSA-44":
                        is_valid = ml_dsa_verify(public_key, digest_to_check, sig)
                    else:
                        if algo == "RSA":
                            cert.public_key().verify(
                                sig,
                                digest_to_check,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA3_256() if hash_algo == "sha3_256" else hashes.SHA3_512()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA3_256() if hash_algo == "sha3_256" else hashes.SHA3_512()
                            )
                        elif algo == "ECDSA":
                            cert.public_key().verify(
                                sig,
                                digest_to_check,
                                ec.ECDSA(hashes.SHA3_256() if hash_algo == "sha3_256" else hashes.SHA3_512())
                            )
                        elif algo == "Ed25519":
                            cert.public_key().verify(sig, digest_to_check)
                        is_valid = True
                except Exception:
                    is_valid = False

                if not is_valid:
                    self.verify_status.config(text="❌ Signature INVALID", bootstyle="danger")
                    self.log("Verification FAILED: Signature is invalid.")
                    return

                if algo != "ML-DSA-44":
                    # Check certificate validity period
                    now = datetime.datetime.utcnow()
                    if now < cert.not_valid_before or now > cert.not_valid_after:
                        self.verify_status.config(text="❌ Certificate Expired or Not Yet Valid", bootstyle="danger")
                        self.log("Verification FAILED: Certificate is not valid at current time.")
                        return

                    self.verify_status.config(text=f"✅ Signature VALID (Signed by: {meta['signed_by']}) | Certificate Valid Until: {cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')}", bootstyle="success")
                    self.log("Verification SUCCESS: Signature is valid and certificate is within validity period.")

                    # Display details in a more user-friendly way
                    self.details_text.config(state=tk.NORMAL)
                    self.details_text.insert(tk.END, "Certificate Details:\n\n")
                    self.details_text.insert(tk.END, f"Subject: {cert.subject.rfc4514_string()}\n\n")
                    self.details_text.insert(tk.END, f"Issuer: {cert.issuer.rfc4514_string()}\n\n")
                    self.details_text.insert(tk.END, f"Serial Number: {cert.serial_number}\n\n")
                    self.details_text.insert(tk.END, "Validity Period:\n")
                    self.details_text.insert(tk.END, f"  From: {cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    self.details_text.insert(tk.END, f"  To: {cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    self.details_text.insert(tk.END, f"Signature Algorithm: {cert.signature_hash_algorithm.name}\n\n")
                    self.details_text.insert(tk.END, f"Hash Algorithm: {hash_algo}\n\n")
                    self.details_text.insert(tk.END, "Extensions:\n")
                    for ext in cert.extensions:
                        self.details_text.insert(tk.END, f"  - {ext.oid._name} (Critical: {ext.critical}): {ext.value}\n")
                    self.details_text.insert(tk.END, f"\nSigned At: {meta.get('signed_at', 'N/A')}\n")
                    self.details_text.config(state=tk.DISABLED)
                else:
                    self.verify_status.config(text=f"✅ Signature VALID (Signed by: {meta['signed_by']})", bootstyle="success")
                    self.log("Verification SUCCESS: Signature is valid.")

                    # Display details for ML-DSA
                    self.details_text.config(state=tk.NORMAL)
                    self.details_text.insert(tk.END, "Post-Quantum Signature Details:\n\n")
                    self.details_text.insert(tk.END, f"Algorithm: {algo} (Dilithium)\n\n")
                    self.details_text.insert(tk.END, f"Hash Algorithm: {hash_algo}\n\n")
                    self.details_text.insert(tk.END, f"Signed At: {meta.get('signed_at', 'N/A')}\n")
                    self.details_text.config(state=tk.DISABLED)

        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("Verification Error", str(e))


# Run the app
