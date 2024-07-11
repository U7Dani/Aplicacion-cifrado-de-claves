import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import base64
import pyperclip

def hash_message(message, hash_type):
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

def hmac_message(message, key, hash_type):
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

def encrypt_message(message, key, algo, nonce, padding_type):
    key_bytes = bytes.fromhex(key)
    nonce_bytes = base64.b64decode(nonce) if nonce else None
    if algo == 'ChaCha20':
        cipher = ChaCha20.new(key=key_bytes)
        ct_bytes = cipher.encrypt(message.encode())
        nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    elif algo == 'AES-CBC':
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        if padding_type == 'PKCS7':
            ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        else:
            ct_bytes = cipher.encrypt(message.encode())
        nonce = base64.b64encode(cipher.iv).decode('utf-8')
    elif algo == 'AES-GCM':
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
        ct_bytes, tag = cipher.encrypt_and_digest(message.encode())
        nonce = base64.b64encode(cipher.nonce).decode('utf-8')
        ct_bytes = ct_bytes + tag
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return nonce + ct

def decrypt_message(ciphertext, key, algo, nonce, padding_type):
    key_bytes = bytes.fromhex(key)
    nonce_bytes = base64.b64decode(ciphertext[:24])
    ct = base64.b64decode(ciphertext[24:])
    if algo == 'ChaCha20':
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce_bytes)
        pt = cipher.decrypt(ct)
    elif algo == 'AES-CBC':
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=nonce_bytes)
        if padding_type == 'PKCS7':
            pt = unpad(cipher.decrypt(ct), AES.block_size)
        else:
            pt = cipher.decrypt(ct)
    elif algo == 'AES-GCM':
        ct, tag = ct[:-16], ct[-16:]
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
        pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode('utf-8')

def generate_key():
    key = get_random_bytes(32)
    key_hex = key.hex()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key_hex)

def generate_nonce():
    nonce = get_random_bytes(12)
    nonce_base64 = base64.b64encode(nonce).decode('utf-8')
    nonce_entry.delete(0, tk.END)
    nonce_entry.insert(0, nonce_base64)

def on_hash():
    message = message_entry.get()
    hash_type = hash_type_combo.get()
    result = hash_message(message, hash_type)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, result)

def on_hmac():
    message = message_entry.get()
    key = key_entry.get()
    hash_type = hash_type_combo.get()
    result = hmac_message(message, key, hash_type)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, result)

def on_encrypt():
    message = message_entry.get()
    key = key_entry.get()
    algo = algo_combo.get()
    nonce = nonce_entry.get()
    padding_type = padding_combo.get() if algo == 'AES-CBC' else None
    result = encrypt_message(message, key, algo, nonce, padding_type)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, result)

def on_decrypt():
    ciphertext = message_entry.get()
    key = key_entry.get()
    algo = algo_combo.get()
    nonce = nonce_entry.get()
    padding_type = padding_combo.get() if algo == 'AES-CBC' else None
    try:
        result = decrypt_message(ciphertext, key, algo, nonce, padding_type)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt: {str(e)}")
        return
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, result)

def save_key():
    key = key_entry.get()
    file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
    if file_path:
        with open(file_path, 'w') as key_file:
            key_file.write(key)
        messagebox.showinfo("Success", "Key saved successfully")

def load_key():
    file_path = filedialog.askopenfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
    if file_path:
        with open(file_path, 'r') as key_file:
            key = key_file.read().strip()
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key)

def copy_result():
    result = result_text.get("1.0", tk.END).strip()
    pyperclip.copy(result)
    messagebox.showinfo("Copied", "Result copied to clipboard")

def reset_fields():
    message_entry.delete(0, tk.END)
    key_entry.delete(0, tk.END)
    nonce_entry.delete(0, tk.END)
    hash_type_combo.current(0)
    algo_combo.current(0)
    padding_combo.current(0)
    result_text.delete('1.0', tk.END)

root = tk.Tk()
root.title("Hash and Encryption App")

mainframe = ttk.Frame(root, padding="10")
mainframe.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Labels and Entries
ttk.Label(mainframe, text="Message:").grid(row=0, column=0, sticky=tk.W)
message_entry = ttk.Entry(mainframe, width=50)
message_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Key (for HMAC/Encryption):").grid(row=1, column=0, sticky=tk.W)
key_entry = ttk.Entry(mainframe, width=50)
key_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Nonce:").grid(row=2, column=0, sticky=tk.W)
nonce_entry = ttk.Entry(mainframe, width=50)
nonce_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Hash Type:").grid(row=3, column=0, sticky=tk.W)
hash_type_combo = ttk.Combobox(mainframe, values=['sha256', 'sha512', 'sha3_256', 'sha3_512'])
hash_type_combo.grid(row=3, column=1, sticky=(tk.W, tk.E))
hash_type_combo.current(0)

ttk.Label(mainframe, text="Encryption Algorithm:").grid(row=4, column=0, sticky=tk.W)
algo_combo = ttk.Combobox(mainframe, values=['ChaCha20', 'AES-CBC', 'AES-GCM'])
algo_combo.grid(row=4, column=1, sticky=(tk.W, tk.E))
algo_combo.current(0)

ttk.Label(mainframe, text="Padding:").grid(row=5, column=0, sticky=tk.W)
padding_combo = ttk.Combobox(mainframe, values=['PKCS7', 'None'])
padding_combo.grid(row=5, column=1, sticky=(tk.W, tk.E))
padding_combo.current(0)

# Buttons
ttk.Button(mainframe, text="Hash", command=on_hash).grid(row=6, column=0, sticky=tk.W)
ttk.Button(mainframe, text="HMAC", command=on_hmac).grid(row=6, column=1, sticky=tk.W)
ttk.Button(mainframe, text="Encrypt", command=on_encrypt).grid(row=6, column=2, sticky=tk.W)
ttk.Button(mainframe, text="Decrypt", command=on_decrypt).grid(row=6, column=3, sticky=tk.W)
ttk.Button(mainframe, text="Generate Key", command=generate_key).grid(row=7, column=0, sticky=tk.W)
ttk.Button(mainframe, text="Generate Nonce", command=generate_nonce).grid(row=7, column=1, sticky=tk.W)
ttk.Button(mainframe, text="Save Key", command=save_key).grid(row=7, column=2, sticky=tk.W)
ttk.Button(mainframe, text="Load Key", command=load_key).grid(row=7, column=3, sticky=tk.W)
ttk.Button(mainframe, text="Copy Result", command=copy_result).grid(row=8, column=2, sticky=tk.W)
ttk.Button(mainframe, text="Reset", command=reset_fields).grid(row=8, column=3, sticky=tk.W)

# Result Text Box
ttk.Label(mainframe, text="Result:").grid(row=9, column=0, sticky=tk.W)
result_text = tk.Text(mainframe, width=60, height=10)
result_text.grid(row=10, column=0, columnspan=4, sticky=(tk.W, tk.E))

root.mainloop()
