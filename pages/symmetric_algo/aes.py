import streamlit as st
import time
import zipfile
from io import BytesIO
from typing import Literal

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

st.set_page_config(page_title="Crypto Playground - Symmetric", page_icon="🔒")

# --- Session state init ---
for algo in ['aes', 'des', '3des']:
    if f'{algo}_btn_disabled' not in st.session_state:
        st.session_state[f'{algo}_btn_disabled'] = True
    if f'{algo}_btn_tooltip' not in st.session_state:
        st.session_state[f'{algo}_btn_tooltip'] = ":red[Please fill in all required fields.]"

# --- Common ---
def get_cipher(algorithm: Literal['AES', 'DES', '3DES'], key: bytes, iv: bytes):
    algo_map = {
        'AES': algorithms.AES,
        'DES': algorithms.DES,
        '3DES': algorithms.TripleDES
    }
    return Cipher(algo_map[algorithm](key), modes.CBC(iv), backend=default_backend())

def pad_data(data: bytes, block_size: int) -> bytes:
    padder = sym_padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data: bytes, block_size: int) -> bytes:
    unpadder = sym_padding.PKCS7(block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def symmetric_tab(algorithm: Literal['AES', 'DES', '3DES']):
    st.subheader(f"🔒 {algorithm} Encryption & Decryption")
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)

    with try_container:
        mode = st.selectbox("Mode", ("Encrypt", "Decrypt"), key=f"{algorithm}_mode")
        key_input = st.text_input("Enter key (hex)", key=f"{algorithm}_key")
        iv_input = st.text_input("Enter IV (hex)", key=f"{algorithm}_iv")
        input_text = st.text_area("Enter text", height=150, key=f"{algorithm}_text")

        key_bytes = bytes.fromhex(key_input) if key_input else b''
        iv_bytes = bytes.fromhex(iv_input) if iv_input else b''
        block_size_map = {'AES': 128, 'DES': 64, '3DES': 64}

        input_ok = all([key_bytes, iv_bytes, input_text])
        st.session_state[f"{algorithm}_btn_disabled"] = not input_ok

        if st.button("✨ GO!", disabled=st.session_state[f"{algorithm}_btn_disabled"], key=f"{algorithm}_go"):
            try:
                cipher = get_cipher(algorithm, key_bytes, iv_bytes)
                if mode == "Encrypt":
                    encryptor = cipher.encryptor()
                    padded_data = pad_data(input_text.encode(), block_size_map[algorithm])
                    output = encryptor.update(padded_data) + encryptor.finalize()
                    output_text = output.hex()
                else:
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(bytes.fromhex(input_text)) + decryptor.finalize()
                    output_text = unpad_data(decrypted, block_size_map[algorithm]).decode()

                output_container.markdown(f"```\n{output_text}\n```)"
)
            except Exception as e:
                st.error(f"Error: {e}", icon="🚨")

# --- Run Interface ---
tab1, tab2, tab3 = st.tabs(["🟣 AES", "🟢 DES", "🔵 3DES"])
with tab1: symmetric_tab('AES')
with tab2: symmetric_tab('DES')
with tab3: symmetric_tab('3DES')