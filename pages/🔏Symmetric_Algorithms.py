# pages/🔏Symmetric_Algorithms.py

import streamlit as st
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
import base64

# — Padding Helpers —
def pad(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

# — Encryption / Decryption Functions —
def aes_encrypt(data: bytes, key: bytes):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(b64: str, key: bytes):
    raw = base64.b64decode(b64)
    iv, ct = raw[:AES.block_size], raw[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))

def des_encrypt(data: bytes, key: bytes):
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, DES.block_size))
    return base64.b64encode(iv + ct).decode()

def des_decrypt(b64: str, key: bytes):
    raw = base64.b64decode(b64)
    iv, ct = raw[:DES.block_size], raw[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))

def triple_des_encrypt(data: bytes, key: bytes):
    iv = get_random_bytes(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, DES3.block_size))
    return base64.b64encode(iv + ct).decode()

def triple_des_decrypt(b64: str, key: bytes):
    raw = base64.b64decode(b64)
    iv, ct = raw[:DES3.block_size], raw[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))

# — Streamlit UI —
st.set_page_config(page_title="Symmetric Algorithms", page_icon="🔏", layout="wide")
st.header("🔏 Symmetric Encryption")

st.markdown("""
Symmetric cryptography uses the *same* key for encryption and decryption.  
Choose an algorithm, operation, and input mode below.
""")
st.divider()

# — Sidebar Controls —
algo = st.sidebar.selectbox("Algorithm", ["AES", "DES", "3DES"])
operation = st.sidebar.radio("Operation", ["Encrypt", "Decrypt"])
mode = st.sidebar.radio("Mode", ["Text", "File"])

# — Key & Input Fields —
# Generate random key button
key_len_map = {"AES": 16, "DES": 8, "3DES": 24}
if st.sidebar.button("🔑 Generate Key"):
    st.session_state["sym_key"] = get_random_bytes(key_len_map[algo]).hex()

key_hex = st.sidebar.text_input(
    "Key (hex)", 
    value=st.session_state.get("sym_key", ""), 
    help=f"{key_len_map[algo]} bytes = {key_len_map[algo]*8} bits"
)

st.sidebar.markdown("---")

# — Main Panel —
output = None

if mode == "Text":
    text_in = st.text_area("Enter text or (for decrypt) base64 ciphertext")
    if st.button("🚀 GO"):
        if not key_hex or not text_in:
            st.error("Please supply both a key and input text.")
        else:
            try:
                key = bytes.fromhex(key_hex)
                data = text_in.encode() if operation=="Encrypt" else text_in
                if operation == "Encrypt":
                    if algo == "AES":
                        output = aes_encrypt(data, key)
                    elif algo == "DES":
                        output = des_encrypt(data, key)
                    else:
                        output = triple_des_encrypt(data, key)
                else:
                    if algo == "AES":
                        output = aes_decrypt(data, key).decode()
                    elif algo == "DES":
                        output = des_decrypt(data, key).decode()
                    else:
                        output = triple_des_decrypt(data, key).decode()
                st.success("✅ Result:")
                st.code(output)
            except Exception as e:
                st.error(f"Error: {e}")

else:  # File mode
    upload = st.file_uploader("Upload file")
    if upload and st.button("🚀 GO"):
        key = bytes.fromhex(key_hex) if key_hex else b''
        file_bytes = upload.read()
        if not key_hex or not file_bytes:
            st.error("Please provide both key and file.")
        else:
            try:
                if operation == "Encrypt":
                    if algo == "AES":
                        result_b64 = aes_encrypt(file_bytes, key)
                        out_bytes = result_b64.encode()
                        out_name = f"enc_{upload.name}.txt"
                    elif algo == "DES":
                        result_b64 = des_encrypt(file_bytes, key)
                        out_bytes = result_b64.encode()
                        out_name = f"enc_{upload.name}.txt"
                    else:
                        result_b64 = triple_des_encrypt(file_bytes, key)
                        out_bytes = result_b64.encode()
                        out_name = f"enc_{upload.name}.txt"
                else:
                    b64 = file_bytes.decode()
                    if algo == "AES":
                        out_bytes = aes_decrypt(b64, key)
                    elif algo == "DES":
                        out_bytes = des_decrypt(b64, key)
                    else:
                        out_bytes = triple_des_decrypt(b64, key)
                    out_name = f"dec_{upload.name}"
                st.success("✅ Done!")
                st.download_button("⬇️ Download Result", data=out_bytes, file_name=out_name)
            except Exception as e:
                st.error(f"Error: {e}")

st.markdown("---")
st.write("🔐 Powered by PyCryptodome")
