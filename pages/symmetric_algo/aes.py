import streamlit as st
import os
from typing import Literal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

st.set_page_config(
    page_title="Crypto Playground - Symmetric",
    page_icon="🔒",
    layout="wide"
)

# --- Helpers ---
def get_cipher(algorithm: Literal['AES', 'DES', '3DES'], key: bytes, iv: bytes):
    algo_map = {
        'AES': algorithms.AES,
        'DES': algorithms.DES,
        '3DES': algorithms.TripleDES
    }
    return Cipher(algo_map[algorithm](key), modes.CBC(iv), backend=default_backend())

def pad_data(data: bytes, block_bits: int) -> bytes:
    padder = sym_padding.PKCS7(block_bits).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data: bytes, block_bits: int) -> bytes:
    unpadder = sym_padding.PKCS7(block_bits).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def generate_random_hex(n_bytes: int) -> str:
    return os.urandom(n_bytes).hex()

# --- Single-tab renderer ---
def symmetric_tab(algorithm: Literal['AES', 'DES', '3DES']):
    st.subheader(f"🔒 {algorithm} Encryption & Decryption")

    # Expanders
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)

    with try_container:
        mode      = st.selectbox("Mode", ("Encrypt", "Decrypt"), key=f"{algorithm}_mode")
        key_input = st.text_input("Key (hex)", key=f"{algorithm}_key")
        iv_input  = st.text_input("IV  (hex)", key=f"{algorithm}_iv")
        user_text = st.text_area("Message (hex for decrypt)", height=150, key=f"{algorithm}_text")

        # Generate random key/iv buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔑 Gen Key", key=f"{algorithm}_gen_key"):
                n = {'AES':32, 'DES':8, '3DES':24}[algorithm]
                st.session_state[f"{algorithm}_key"] = generate_random_hex(n)
        with col2:
            if st.button("🔐 Gen IV", key=f"{algorithm}_gen_iv"):
                b = {'AES':16, 'DES':8, '3DES':8}[algorithm]
                st.session_state[f"{algorithm}_iv"] = generate_random_hex(b)

        # Validate hex & lengths
        block_map = {'AES':128, 'DES':64, '3DES':64}
        key_lens  = {'AES':(16,24,32), 'DES':(8,), '3DES':(16,24)}
        iv_len    = block_map[algorithm]//8

        error = None
        try:
            key_bytes = bytes.fromhex(key_input)
            iv_bytes  = bytes.fromhex(iv_input)
        except ValueError:
            error = "Key/IV must be valid hex."
        else:
            if len(key_bytes) not in key_lens[algorithm]:
                error = f"{algorithm} key must be {key_lens[algorithm]} bytes."
            elif len(iv_bytes) != iv_len:
                error = f"{algorithm} IV must be {iv_len} bytes."
            elif not user_text:
                error = "Please enter a message."

        # Disable GO if error present
        disabled = error is not None
        tooltip  = error if error else None

        if error:
            st.warning(error, icon="⚠️")

        if st.button("✨ GO!", disabled=disabled, help=tooltip, key=f"{algorithm}_go"):
            try:
                cipher = get_cipher(algorithm, key_bytes, iv_bytes)

                if mode == "Encrypt":
                    encryptor = cipher.encryptor()
                    padded    = pad_data(user_text.encode("utf-8"), block_map[algorithm])
                    result    = encryptor.update(padded) + encryptor.finalize()
                    output    = result.hex()
                else:
                    decryptor = cipher.decryptor()
                    ct_bytes  = bytes.fromhex(user_text.strip())
                    decrypted = decryptor.update(ct_bytes) + decryptor.finalize()
                    output    = unpad_data(decrypted, block_map[algorithm]).decode("utf-8")

                output_container.markdown(f"```\n{output}\n```")
            except Exception as e:
                st.error(f"Error: {e}", icon="🚨")

# --- Render tabs ---
tab1, tab2, tab3 = st.tabs(["🟣 AES", "🟢 DES", "🔵 3DES"])
with tab1: symmetric_tab('AES')
with tab2: symmetric_tab('DES')
with tab3: symmetric_tab('3DES')