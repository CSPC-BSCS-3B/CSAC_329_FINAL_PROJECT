# pages/🔏Symmetric_Algorithms.py
import streamlit as st
from Cryptodome.Cipher import AES, DES, DES3
from Cryptodome.Random import get_random_bytes
import base64
import time

# --- Session state init ---
for algo in ['aes', 'des', '3des']:
    if f'{algo}_btn_disabled' not in st.session_state:
        st.session_state[f'{algo}_btn_disabled'] = True
    if f'{algo}_btn_tooltip' not in st.session_state:
        st.session_state[f'{algo}_btn_tooltip'] = ":red[Please fill in all required fields.]"

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
    return unpad(cipher.decrypt(ct))

# — Streamlit UI —
st.set_page_config(page_title="Symmetric Algorithms", page_icon="🔏")
st.header("🔏 Symmetric Encryption")

st.markdown("""
Symmetric cryptography uses the *same* key for encryption and decryption.  
Choose an algorithm, operation, and input mode below.
""")
st.divider()

# — AES Tab —
def aes_tab():
    st.subheader("🔐 AES Encryption & Decryption")
    key_container = st.expander("Key generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)
    
    with key_container:
        if st.button("🔑 Generate AES Key", key="generate_aes"):
            st.session_state["aes_key"] = get_random_bytes(16).hex()
            st.toast("Generated new AES key", icon="🔑")
        
        key_hex = st.text_input(
            "AES Key (hex, 16 bytes = 128 bits)", 
            value=st.session_state.get("aes_key", ""), 
            key="aes_key_input"
        )
    
    with try_container:
        operation = st.radio("Operation", ["Encrypt", "Decrypt"], key="aes_operation")
        mode = st.radio("Mode", ["Text", "File"], horizontal=True, key="aes_mode")
        
        if mode == "Text":
            input_text = st.text_area("Enter text or base64", height=150, key="aes_text")
            
            if key_hex and input_text:
                st.session_state.aes_btn_disabled = False
            else:
                st.session_state.aes_btn_disabled = True
                
            if st.button("✨ Process", disabled=st.session_state.aes_btn_disabled, key="aes_go"):
                try:
                    key = bytes.fromhex(key_hex)
                    data = input_text.encode() if operation=="Encrypt" else input_text
                    
                    if operation == "Encrypt":
                        output = aes_encrypt(data, key)
                    else:
                        output = aes_decrypt(data, key).decode()
                        
                    output_container.markdown(f"```\n{output}\n```")
                except Exception as e:
                    st.error(f"Error: {e}", icon="🚨")
        else:  # File mode
            upload = st.file_uploader("Upload file", key="aes_file")
            
            if upload and key_hex:
                st.session_state.aes_btn_disabled = False
            else:
                st.session_state.aes_btn_disabled = True
                
            if st.button("✨ Process", disabled=st.session_state.aes_btn_disabled, key="aes_file_go"):
                try:
                    key = bytes.fromhex(key_hex)
                    file_bytes = upload.read()
                    
                    if operation == "Encrypt":
                        result_b64 = aes_encrypt(file_bytes, key)
                        out_bytes = result_b64.encode()
                        out_name = f"enc_{upload.name}.txt"
                    else:
                        b64 = file_bytes.decode()
                        out_bytes = aes_decrypt(b64, key)
                        out_name = f"dec_{upload.name}"
                        
                    output_container.success("✅ Processing complete!")
                    output_container.download_button(
                        "⬇️ Download Result", 
                        data=out_bytes, 
                        file_name=out_name,
                        key="aes_download"
                    )
                except Exception as e:
                    st.error(f"Error: {e}", icon="🚨")

# — DES Tab —
def des_tab():
    st.subheader("🔒 DES Encryption & Decryption")
    key_container = st.expander("Key generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)
    
    with key_container:
        if st.button("🔑 Generate DES Key", key="generate_des"):
            st.session_state["des_key"] = get_random_bytes(8).hex()
            st.toast("Generated new DES key", icon="🔑")
        
        key_hex = st.text_input(
            "DES Key (hex, 8 bytes = 64 bits)", 
            value=st.session_state.get("des_key", ""), 
            key="des_key_input"
        )
    
    with try_container:
        operation = st.radio("Operation", ["Encrypt", "Decrypt"], key="des_operation")
        mode = st.radio("Mode", ["Text", "File"], horizontal=True, key="des_mode")
        
        if mode == "Text":
            input_text = st.text_area("Enter text or base64", height=150, key="des_text")
            
            if key_hex and input_text:
                st.session_state.des_btn_disabled = False
            else:
                st.session_state.des_btn_disabled = True
                
            if st.button("✨ Process", disabled=st.session_state.des_btn_disabled, key="des_go"):
                try:
                    key = bytes.fromhex(key_hex)
                    data = input_text.encode() if operation=="Encrypt" else input_text
                    
                    if operation == "Encrypt":
                        output = des_encrypt(data, key)
                    else:
                        output = des_decrypt(data, key).decode()
                        
                    output_container.markdown(f"```\n{output}\n```")
                except Exception as e:
                    st.error(f"Error: {e}", icon="🚨")
        else:  # File mode
            upload = st.file_uploader("Upload file", key="des_file")
            
            if upload and key_hex:
                st.session_state.des_btn_disabled = False
            else:
                st.session_state.des_btn_disabled = True
                
            if st.button("✨ Process", disabled=st.session_state.des_btn_disabled, key="des_file_go"):
                try:
                    key = bytes.fromhex(key_hex)
                    file_bytes = upload.read()
                    
                    if operation == "Encrypt":
                        result_b64 = des_encrypt(file_bytes, key)
                        out_bytes = result_b64.encode()
                        out_name = f"enc_{upload.name}.txt"
                    else:
                        b64 = file_bytes.decode()
                        out_bytes = des_decrypt(b64, key)
                        out_name = f"dec_{upload.name}"
                        
                    output_container.success("✅ Processing complete!")
                    output_container.download_button(
                        "⬇️ Download Result", 
                        data=out_bytes, 
                        file_name=out_name,
                        key="des_download"
                    )
                except Exception as e:
                    st.error(f"Error: {e}", icon="🚨")

# — 3DES Tab —
def triple_des_tab():
    st.subheader("🔏 Triple DES Encryption & Decryption")
    key_container = st.expander("Key generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)
    
    with key_container:
        if st.button("🔑 Generate 3DES Key", key="generate_3des"):
            st.session_state["3des_key"] = get_random_bytes(24).hex()
            st.toast("Generated new 3DES key", icon="🔑")
        
        key_hex = st.text_input(
            "3DES Key (hex, 24 bytes = 192 bits)", 
            value=st.session_state.get("3des_key", ""), 
            key="3des_key_input"
        )
    
    with try_container:
        operation = st.radio("Operation", ["Encrypt", "Decrypt"], key="3des_operation")
        mode = st.radio("Mode", ["Text", "File"], horizontal=True, key="3des_mode")
        
        if mode == "Text":
            input_text = st.text_area("Enter text or base64", height=150, key="3des_text")
            
            if key_hex and input_text:
                st.session_state['3des_btn_disabled'] = False
            else:
                st.session_state['3des_btn_disabled'] = True
                
            if st.button("✨ Process", disabled=st.session_state['3des_btn_disabled'], key="3des_go"):
                try:
                    key = bytes.fromhex(key_hex)
                    data = input_text.encode() if operation=="Encrypt" else input_text
                    
                    if operation == "Encrypt":
                        output = triple_des_encrypt(data, key)
                    else:
                        output = triple_des_decrypt(data, key).decode()
                        
                    output_container.markdown(f"```\n{output}\n```")
                except Exception as e:
                    st.error(f"Error: {e}", icon="🚨")
        else:  # File mode
            upload = st.file_uploader("Upload file", key="3des_file")
            
            if upload and key_hex:
                st.session_state['3des_btn_disabled'] = False
            else:
                st.session_state['3des_btn_disabled'] = True
                
            if st.button("✨ Process", disabled=st.session_state['3des_btn_disabled'], key="3des_file_go"):
                try:
                    key = bytes.fromhex(key_hex)
                    file_bytes = upload.read()
                    
                    if operation == "Encrypt":
                        result_b64 = triple_des_encrypt(file_bytes, key)
                        out_bytes = result_b64.encode()
                        out_name = f"enc_{upload.name}.txt"
                    else:
                        b64 = file_bytes.decode()
                        out_bytes = triple_des_decrypt(b64, key)
                        out_name = f"dec_{upload.name}"
                        
                    output_container.success("✅ Processing complete!")
                    output_container.download_button(
                        "⬇️ Download Result", 
                        data=out_bytes, 
                        file_name=out_name,
                        key="3des_download"
                    )
                except Exception as e:
                    st.error(f"Error: {e}", icon="🚨")

# --- Run Interface ---
tab1, tab2, tab3 = st.tabs(["🔐 AES", "🔒 DES", "🔏 3DES"])
with tab1: aes_tab()
with tab2: des_tab()
with tab3: triple_des_tab()

st.markdown("---")
st.markdown("""
**About Symmetric Encryption:**

Symmetric encryption uses the same key for both encryption and decryption. It's generally faster than asymmetric encryption but requires a secure method to share the key between parties.

- **AES (Advanced Encryption Standard)**: The current industry standard, offering excellent security and performance. Supports key sizes of 128, 192, and 256 bits.
- **DES (Data Encryption Standard)**: An older algorithm with a 56-bit effective key length, now considered insecure for modern applications.
- **3DES (Triple DES)**: Applies the DES algorithm three times to each data block, providing improved security over standard DES.

All implementations on this page use CBC (Cipher Block Chaining) mode with proper padding.
""")
st.write("🔐 Powered by PyCryptodome")
