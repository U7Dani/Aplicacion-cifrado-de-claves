import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import hmac
import base64
import pyperclip

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto App")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, expand=True)

        # Cifrado Simétrico
        self.sym_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.sym_tab, text='Cifrado Simétrico')
        self.create_sym_widgets()

        # Cifrado Asimétrico
        self.asym_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.asym_tab, text='Cifrado Asimétrico')
        self.create_asym_widgets()

        # Hashing y HMAC
        self.hash_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.hash_tab, text='Hashing y HMAC')
        self.create_hash_widgets()

        # Gestión de Claves
        self.key_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.key_tab, text='Gestión de Claves')
        self.create_key_widgets()

    def create_sym_widgets(self):
        ttk.Label(self.sym_tab, text="Message:").grid(row=0, column=0, sticky=tk.W)
        self.message_entry = ttk.Entry(self.sym_tab, width=50)
        self.message_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(self.sym_tab, text="Key:").grid(row=1, column=0, sticky=tk.W)
        self.key_entry = ttk.Entry(self.sym_tab, width=50)
        self.key_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        ttk.Button(self.sym_tab, text="Generate Key", command=self.generate_key).grid(row=1, column=2, sticky=tk.W)
        
        ttk.Label(self.sym_tab, text="Nonce:").grid(row=2, column=0, sticky=tk.W)
        self.nonce_entry = ttk.Entry(self.sym_tab, width=50)
        self.nonce_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        ttk.Button(self.sym_tab, text="Generate Nonce", command=self.generate_nonce).grid(row=2, column=2, sticky=tk.W)

        ttk.Label(self.sym_tab, text="Algorithm:").grid(row=3, column=0, sticky=tk.W)
        self.algo_combo = ttk.Combobox(self.sym_tab, values=['AES-CBC', 'AES-GCM', 'ChaCha20', 'ChaCha20-Poly1305'])
        self.algo_combo.grid(row=3, column=1, sticky=(tk.W, tk.E))
        self.algo_combo.current(0)
        
        ttk.Label(self.sym_tab, text="Padding:").grid(row=4, column=0, sticky=tk.W)
        self.padding_combo = ttk.Combobox(self.sym_tab, values=['PKCS7', 'None'])
        self.padding_combo.grid(row=4, column=1, sticky=(tk.W, tk.E))
        self.padding_combo.current(0)
        
        ttk.Button(self.sym_tab, text="Encrypt", command=self.on_encrypt).grid(row=5, column=0, sticky=tk.W)
        ttk.Button(self.sym_tab, text="Decrypt", command=self.on_decrypt).grid(row=5, column=1, sticky=tk.W)

        ttk.Label(self.sym_tab, text="Result:").grid(row=6, column=0, sticky=tk.W)
        self.result_text_sym = tk.Text(self.sym_tab, width=60, height=10)
        self.result_text_sym.grid(row=7, column=0, columnspan=5, sticky=(tk.W, tk.E))
        ttk.Button(self.sym_tab, text="Copy Result", command=lambda: self.copy_to_clipboard(self.result_text_sym.get('1.0', tk.END).strip())).grid(row=8, column=2, sticky=tk.W)

    def create_asym_widgets(self):
        ttk.Label(self.asym_tab, text="Message:").grid(row=0, column=0, sticky=tk.W)
        self.message_entry_asym = ttk.Entry(self.asym_tab, width=50)
        self.message_entry_asym.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(self.asym_tab, text="Private Key Path:").grid(row=1, column=0, sticky=tk.W)
        self.private_key_path_entry = ttk.Entry(self.asym_tab, width=50)
        self.private_key_path_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        ttk.Button(self.asym_tab, text="Browse", command=self.browse_private_key).grid(row=1, column=2, sticky=tk.W)
        
        ttk.Label(self.asym_tab, text="Public Key Path:").grid(row=2, column=0, sticky=tk.W)
        self.public_key_path_entry = ttk.Entry(self.asym_tab, width=50)
        self.public_key_path_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        ttk.Button(self.asym_tab, text="Browse", command=self.browse_public_key).grid(row=2, column=2, sticky=tk.W)

        ttk.Button(self.asym_tab, text="Generate Key Pair", command=self.generate_rsa_keys).grid(row=3, column=0, sticky=tk.W)
        ttk.Button(self.asym_tab, text="Encrypt", command=self.on_rsa_encrypt).grid(row=3, column=1, sticky=tk.W)
        ttk.Button(self.asym_tab, text="Decrypt", command=self.on_rsa_decrypt).grid(row=3, column=2, sticky=tk.W)

        ttk.Label(self.asym_tab, text="Original Message:").grid(row=4, column=0, sticky=tk.W)
        self.original_message_entry = ttk.Entry(self.asym_tab, width=50)
        self.original_message_entry.grid(row=4, column=1, sticky=(tk.W, tk.E))
        
        ttk.Button(self.asym_tab, text="Verify", command=self.on_rsa_verify).grid(row=4, column=2, sticky=tk.W)

        ttk.Label(self.asym_tab, text="Result:").grid(row=5, column=0, sticky=tk.W)
        self.result_text_asym = tk.Text(self.asym_tab, width=60, height=10)
        self.result_text_asym.grid(row=6, column=0, columnspan=5, sticky=(tk.W, tk.E))
        ttk.Button(self.asym_tab, text="Copy Result", command=lambda: self.copy_to_clipboard(self.result_text_asym.get('1.0', tk.END).strip())).grid(row=7, column=2, sticky=tk.W)

    def create_hash_widgets(self):
        ttk.Label(self.hash_tab, text="Message:").grid(row=0, column=0, sticky=tk.W)
        self.message_entry_hash = ttk.Entry(self.hash_tab, width=50)
        self.message_entry_hash.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(self.hash_tab, text="Key (for HMAC):").grid(row=1, column=0, sticky=tk.W)
        self.key_entry_hash = ttk.Entry(self.hash_tab, width=50)
        self.key_entry_hash.grid(row=1, column=1, sticky=(tk.W, tk.E))
        ttk.Button(self.hash_tab, text="Generate HMAC Key", command=self.generate_hmac_key).grid(row=1, column=2, sticky=tk.W)

        ttk.Label(self.hash_tab, text="Hash Type:").grid(row=2, column=0, sticky=tk.W)
        self.hash_type_combo = ttk.Combobox(self.hash_tab, values=['sha256', 'sha512', 'sha3_256', 'sha3_512'])
        self.hash_type_combo.grid(row=2, column=1, sticky=(tk.W, tk.E))
        self.hash_type_combo.current(0)
        
        ttk.Button(self.hash_tab, text="Hash", command=self.on_hash).grid(row=3, column=0, sticky=tk.W)
        ttk.Button(self.hash_tab, text="HMAC", command=self.on_hmac).grid(row=3, column=1, sticky=tk.W)

        ttk.Label(self.hash_tab, text="Result:").grid(row=4, column=0, sticky=tk.W)
        self.result_text_hash = tk.Text(self.hash_tab, width=60, height=10)
        self.result_text_hash.grid(row=5, column=0, columnspan=5, sticky=(tk.W, tk.E))
        ttk.Button(self.hash_tab, text="Copy Result", command=lambda: self.copy_to_clipboard(self.result_text_hash.get('1.0', tk.END).strip())).grid(row=6, column=2, sticky=tk.W)

    def create_key_widgets(self):
        ttk.Label(self.key_tab, text="Master Key:").grid(row=0, column=0, sticky=tk.W)
        self.master_key_entry = ttk.Entry(self.key_tab, width=50)
        self.master_key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(self.key_tab, text="Key Size:").grid(row=1, column=0, sticky=tk.W)
        self.master_key_size_combo = ttk.Combobox(self.key_tab, values=[64, 128, 256, 512])
        self.master_key_size_combo.grid(row=1, column=1, sticky=(tk.W, tk.E))
        self.master_key_size_combo.current(2)
        
        ttk.Button(self.key_tab, text="Generate Master Key", command=self.generate_master_key).grid(row=2, column=0, sticky=tk.W)
        ttk.Button(self.key_tab, text="Save Key", command=self.save_key).grid(row=2, column=1, sticky=tk.W)
        ttk.Button(self.key_tab, text="Load Key", command=self.load_key).grid(row=2, column=2, sticky=tk.W)
        ttk.Button(self.key_tab, text="Derive Key", command=self.on_derive_key).grid(row=2, column=3, sticky=tk.W)
        
        ttk.Label(self.key_tab, text="Salt:").grid(row=3, column=0, sticky=tk.W)
        self.salt_entry = ttk.Entry(self.key_tab, width=50)
        self.salt_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))
        ttk.Button(self.key_tab, text="Generate Salt", command=self.generate_salt).grid(row=3, column=2, sticky=tk.W)

        ttk.Label(self.key_tab, text="Derived Key:").grid(row=4, column=0, sticky=tk.W)
        self.derived_key_text = tk.Text(self.key_tab, width=60, height=1)
        self.derived_key_text.grid(row=5, column=0, columnspan=5, sticky=(tk.W, tk.E))
        ttk.Button(self.key_tab, text="Copy Derived Key", command=lambda: self.copy_to_clipboard(self.derived_key_text.get('1.0', tk.END).strip())).grid(row=6, column=3, sticky=tk.W)
        ttk.Button(self.key_tab, text="Copy Salt", command=lambda: self.copy_to_clipboard(self.salt_entry.get())).grid(row=6, column=1, sticky=tk.W)

    def browse_private_key(self):
        file_path = filedialog.askopenfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if file_path:
            self.private_key_path_entry.delete(0, tk.END)
            self.private_key_path_entry.insert(0, file_path)

    def browse_public_key(self):
        file_path = filedialog.askopenfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if file_path:
            self.public_key_path_entry.delete(0, tk.END)
            self.public_key_path_entry.insert(0, file_path)

    def on_hash(self):
        message = self.message_entry_hash.get()
        hash_type = self.hash_type_combo.get()
        result = self.hash_message(message, hash_type)
        self.result_text_hash.delete('1.0', tk.END)
        self.result_text_hash.insert(tk.END, result)

    def on_hmac(self):
        message = self.message_entry_hash.get()
        key = self.key_entry_hash.get()
        hash_type = self.hash_type_combo.get()
        result = self.hmac_message(message, key, hash_type)
        self.result_text_hash.delete('1.0', tk.END)
        self.result_text_hash.insert(tk.END, result)

    def on_encrypt(self):
        message = self.message_entry.get()
        key = self.key_entry.get()
        nonce = self.nonce_entry.get()
        algo = self.algo_combo.get()
        padding = self.padding_combo.get()

        if not key:
            messagebox.showerror("Error", "Key is required for encryption.")
            return

        if not nonce:
            messagebox.showerror("Error", "Nonce is required for encryption.")
            return

        key_bytes = bytes.fromhex(key)
        if len(key_bytes) not in [16, 24, 32]:
            messagebox.showerror("Error", "Incorrect AES key length (must be 16, 24, or 32 bytes).")
            return

        nonce_bytes = bytes.fromhex(nonce)
        if algo == 'AES-CBC' and len(nonce_bytes) != 16:
            messagebox.showerror("Error", "Incorrect IV length for AES-CBC (must be 16 bytes).")
            return
        elif algo == 'AES-GCM' and len(nonce_bytes) != 12:
            messagebox.showerror("Error", "Incorrect nonce length for AES-GCM (must be 12 bytes).")
            return

        if algo == 'AES-CBC' or algo == 'AES-GCM':
            mode = 'CBC' if algo == 'AES-CBC' else 'GCM'
            result = self.encrypt_message_aes(message, key, nonce, mode, padding)
        elif algo == 'ChaCha20':
            result = self.encrypt_message_chacha20(message, key, nonce)
        elif algo == 'ChaCha20-Poly1305':
            result = self.encrypt_message_chacha20_poly1305(message, key, nonce)

        self.result_text_sym.delete('1.0', tk.END)
        self.result_text_sym.insert(tk.END, result)

    def on_decrypt(self):
        ciphertext = self.message_entry.get()
        key = self.key_entry.get()
        nonce = self.nonce_entry.get()
        algo = self.algo_combo.get()
        padding = self.padding_combo.get()

        if not key:
            messagebox.showerror("Error", "Key is required for decryption.")
            return

        if not nonce:
            messagebox.showerror("Error", "Nonce is required for decryption.")
            return

        key_bytes = bytes.fromhex(key)
        if len(key_bytes) not in [16, 24, 32]:
            messagebox.showerror("Error", "Incorrect AES key length (must be 16, 24, or 32 bytes).")
            return

        nonce_bytes = bytes.fromhex(nonce)
        if algo == 'AES-CBC' and len(nonce_bytes) != 16:
            messagebox.showerror("Error", "Incorrect IV length for AES-CBC (must be 16 bytes).")
            return
        elif algo == 'AES-GCM' and len(nonce_bytes) != 12:
            messagebox.showerror("Error", "Incorrect nonce length for AES-GCM (must be 12 bytes).")
            return

        try:
            if algo == 'AES-CBC' or algo == 'AES-GCM':
                mode = 'CBC' if algo == 'AES-CBC' else 'GCM'
                result = self.decrypt_message_aes(ciphertext, key, nonce, mode, padding)
            elif algo == 'ChaCha20':
                result = self.decrypt_message_chacha20(ciphertext, key, nonce)
            elif algo == 'ChaCha20-Poly1305':
                result = self.decrypt_message_chacha20_poly1305(ciphertext, key, nonce)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {str(e)}")
            return

        self.result_text_sym.delete('1.0', tk.END)
        self.result_text_sym.insert(tk.END, result)

    def on_rsa_encrypt(self):
        public_key_path = self.public_key_path_entry.get()
        message_to_encrypt = self.message_entry_asym.get()
        try:
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read()
                )

            encrypted_message = public_key.encrypt(
                message_to_encrypt.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encrypted_message_hex = encrypted_message.hex()
            self.result_text_asym.delete('1.0', tk.END)
            self.result_text_asym.insert(tk.END, encrypted_message_hex)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt: {str(e)}")

    def on_rsa_decrypt(self):
        private_key_path = self.private_key_path_entry.get()
        encrypted_message_hex = self.message_entry_asym.get()
        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )

            encrypted_message_bytes = bytes.fromhex(encrypted_message_hex)
            decrypted_message = private_key.decrypt(
                encrypted_message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.result_text_asym.delete('1.0', tk.END)
            self.result_text_asym.insert(tk.END, decrypted_message.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {str(e)}")

    def on_rsa_verify(self):
        public_key_path = self.public_key_path_entry.get()
        signature_hex = self.message_entry_asym.get()  # Using the message_entry to input signature
        original_message = self.original_message_entry.get().encode('utf-8')  # New entry for the original message

        try:
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read()
                )

            signature_bytes = bytes.fromhex(signature_hex)
            public_key.verify(
                signature_bytes,
                original_message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.result_text_asym.delete('1.0', tk.END)
            self.result_text_asym.insert(tk.END, "La firma es válida.")
        except Exception as e:
            messagebox.showerror("Error", f"La firma no es válida: {str(e)}")

    def generate_master_key(self):
        key_size = int(self.master_key_size_combo.get())
        key = get_random_bytes(key_size // 8).hex()
        self.master_key_entry.delete(0, tk.END)
        self.master_key_entry.insert(0, key)

    def generate_salt(self):
        salt = get_random_bytes(16).hex()
        self.salt_entry.delete(0, tk.END)
        self.salt_entry.insert(0, salt)

    def generate_key(self):
        key = get_random_bytes(32).hex()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

    def generate_nonce(self):
        algo = self.algo_combo.get()
        nonce = get_random_bytes(16 if algo == 'AES-CBC' else 12).hex()
        self.nonce_entry.delete(0, tk.END)
        self.nonce_entry.insert(0, nonce)

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Save private key
        private_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if private_key_path:
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

        # Save public key
        public_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if public_key_path:
            with open(public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

        messagebox.showinfo("Success", "RSA Key Pair generated and saved successfully")

    def generate_hmac_key(self):
        key = get_random_bytes(32).hex()
        self.key_entry_hash.delete(0, tk.END)
        self.key_entry_hash.insert(0, key)

    def save_key(self):
        key = self.key_entry.get()
        salt = self.salt_entry.get()
        file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
        if file_path:
            with open(file_path, 'w') as key_file:
                key_file.write(f"{key}\n{salt}")
            messagebox.showinfo("Success", "Key and salt saved successfully")

    def load_key(self):
        file_path = filedialog.askopenfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
        if file_path:
            with open(file_path, 'r') as key_file:
                key, salt = key_file.read().strip().split('\n')
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key)
            self.salt_entry.delete(0, tk.END)
            self.salt_entry.insert(0, salt)

    def on_derive_key(self):
        master_key = self.master_key_entry.get()
        salt = self.salt_entry.get()
        if not salt:
            messagebox.showerror("Error", "Salt is required")
            return
        derived_key = self.derive_key(master_key, salt)
        self.derived_key_text.delete('1.0', tk.END)
        self.derived_key_text.insert(tk.END, derived_key)

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        messagebox.showinfo("Copied", "Text copied to clipboard")

    def reset_fields(self):
        self.message_entry.delete(0, tk.END)
        self.key_entry.delete(0, tk.END)
        self.nonce_entry.delete(0, tk.END)
        self.hash_type_combo.current(0)
        self.algo_combo.current(0)
        self.padding_combo.current(0)
        self.master_key_entry.delete(0, tk.END)
        self.salt_entry.delete(0, tk.END)
        self.result_text_sym.delete('1.0', tk.END)
        self.derived_key_text.delete('1.0', tk.END)

    def hash_message(self, message, hash_type):
        if hash_type == 'sha256':
            return hashlib.sha256(message.encode()).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(message.encode()).hexdigest()
        elif hash_type == 'sha3_256':
            return hashlib.sha3_256(message.encode()).hexdigest()
        elif hash_type == 'sha3_512':
            return hashlib.sha3_512(message.encode()).hexdigest()
        else:
            return None

    def hmac_message(self, message, key, hash_type):
        key_bytes = bytes.fromhex(key)
        if hash_type == 'sha256':
            return hmac.new(key_bytes, message.encode(), hashlib.sha256).hexdigest()
        elif hash_type == 'sha512':
            return hmac.new(key_bytes, message.encode(), hashlib.sha512).hexdigest()
        elif hash_type == 'sha3_256':
            return hmac.new(key_bytes, message.encode(), hashlib.sha3_256).hexdigest()
        elif hash_type == 'sha3_512':
            return hmac.new(key_bytes, message.encode(), hashlib.sha3_512).hexdigest()
        else:
            return None

    def encrypt_message_aes(self, message, key, nonce, mode, padding):
        key_bytes = bytes.fromhex(key)
        nonce_bytes = bytes.fromhex(nonce)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=nonce_bytes) if mode == 'CBC' else AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
        tag = None
        if padding == 'PKCS7':
            ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        elif padding == 'None':
            ct_bytes = cipher.encrypt(message.encode().ljust(16, b' '))
        else:
            ct_bytes, tag = cipher.encrypt_and_digest(message.encode())
        iv = base64.b64encode(nonce_bytes).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        result = iv + ct
        if mode == 'GCM' and tag is not None:
            result += base64.b64encode(tag).decode('utf-8')
        return result

    def decrypt_message_aes(self, ciphertext, key, nonce, mode, padding):
        key_bytes = bytes.fromhex(key)
        nonce_bytes = bytes.fromhex(nonce)
        if mode == 'CBC':
            ct = base64.b64decode(ciphertext[24:])
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=nonce_bytes)
            if padding == 'PKCS7':
                pt = unpad(cipher.decrypt(ct), AES.block_size)
            elif padding == 'None':
                pt = cipher.decrypt(ct).rstrip()
        elif mode == 'GCM':
            tag = base64.b64decode(ciphertext[-24:])
            ct = base64.b64decode(ciphertext[24:-24])
            cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
            pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode('utf-8')

    def encrypt_message_chacha20(self, message, key, nonce):
        key_bytes = bytes.fromhex(key)
        nonce_bytes = bytes.fromhex(nonce)
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce_bytes)
        ct_bytes = cipher.encrypt(message.encode())
        nonce = base64.b64encode(cipher.nonce).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return nonce + ct

    def decrypt_message_chacha20(self, ciphertext, key, nonce):
        key_bytes = bytes.fromhex(key)
        nonce_bytes = bytes.fromhex(nonce)
        ct = base64.b64decode(ciphertext[24:])
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce_bytes)
        pt = cipher.decrypt(ct)
        return pt.decode('utf-8')

    def encrypt_message_chacha20_poly1305(self, message, key, nonce):
        key_bytes = bytes.fromhex(key)
        nonce_bytes = bytes.fromhex(nonce)
        cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)
        ct_bytes, tag = cipher.encrypt_and_digest(message.encode())
        nonce = base64.b64encode(cipher.nonce).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        tg = base64.b64encode(tag).decode('utf-8')
        return nonce + ct + tg

    def decrypt_message_chacha20_poly1305(self, ciphertext, key, nonce):
        key_bytes = bytes.fromhex(key)
        nonce_bytes = bytes.fromhex(nonce)
        tag = base64.b64decode(ciphertext[-24:])
        ct = base64.b64decode(ciphertext[24:-24])
        cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode('utf-8')

    def derive_key(self, master_key, salt):
        return PBKDF2(master_key, salt, dkLen=32, count=1000000).hex()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
