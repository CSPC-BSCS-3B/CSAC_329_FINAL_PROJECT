import streamlit as st
import time
import zipfile
from io import BytesIO
from typing_extensions import Literal

# Cryptography imports
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding, ec, dsa
)

st.set_page_config(page_title="Crypto Playground", page_icon="🔐")

# --- Session state init ---
for algo in ['rsa', 'ecc', 'dsa']:
    if f'{algo}_btn_disabled' not in st.session_state:
        st.session_state[f'{algo}_btn_disabled'] = True
    if f'{algo}_btn_tooltip' not in st.session_state:
        st.session_state[f'{algo}_btn_tooltip'] = ":red[Please fill in all required fields.]"

# --- Common ---
def download_key_pair(pubkey_bytes: bytes, privkey_bytes: bytes, prefix: str) -> None:
    pubkey_buffer = BytesIO(pubkey_bytes)
    privkey_buffer = BytesIO(privkey_bytes)
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr(f'{prefix}_public_key.pem', pubkey_buffer.getvalue())
        zip_file.writestr(f'{prefix}_private_key.pem', privkey_buffer.getvalue())

    st.download_button(
        label="📁 :orange[Download key pair]",
        data=zip_buffer.getvalue(),
        file_name=f"{prefix}_key_pair.zip",
        mime="application/zip",
        use_container_width=True,
        key=f"download_{prefix}"  # added key here
    )

# --- RSA ---
def rsa_tab():
    st.subheader("🔑 RSA Encryption & Decryption")
    key_container = st.expander("Key pair generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)

    with key_container:
        key_size = st.selectbox("Key size", (2048, 4096), index=0, key="rsa_keysize")  # added key
        pubkey, privkey = generate_rsa_key_pair(key_size)

        if st.button("🔄 Generate RSA key pair", key="generate_rsa"):  # added key
            st.toast("Generating RSA key pair...", icon="🔐")
            time.sleep(1)
            download_key_pair(pubkey, privkey, "rsa")

    with try_container:
        mode = st.selectbox("Mode", ("Encrypt", "Decrypt"), key="rsa_mode")  # added key
        key = st.file_uploader(
            "Upload public key" if mode == "Encrypt" else "Upload private key", type="pem", key="rsa_key_upload"
        )
        input_text = st.text_area("Enter text", height=150, key="rsa_text")

        if key and input_text:
            st.session_state.rsa_btn_disabled = False
            st.session_state.rsa_btn_tooltip = None
        else:
            st.session_state.rsa_btn_disabled = True
            st.session_state.rsa_btn_tooltip = ":red[Please fill in all required fields.]"

        if st.button("✨ GO!", disabled=st.session_state.rsa_btn_disabled, key="rsa_go"):  # added key
            try:
                key_data = key.getvalue()
                if mode == "Encrypt":
                    pubkey = serialization.load_pem_public_key(key_data, backend=default_backend())
                    output = pubkey.encrypt(
                        input_text.encode(),
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    ).hex()
                else:
                    privkey = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                    output = privkey.decrypt(
                        bytes.fromhex(input_text),
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    ).decode()

                output_container.markdown(f"```\n{output}\n```")
            except Exception as e:
                st.error(f"Error: {e}", icon="🚨")

@st.cache_data
def generate_rsa_key_pair(size: int) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=size, backend=default_backend())
    public_key = private_key.public_key()
    return (
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )

# --- ECC ---
def ecc_tab():
    st.subheader("🌀 ECC Sign & Verify")
    key_container = st.expander("Key pair generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)

    with key_container:
        curve_name = st.selectbox("ECC Curve", ("SECP256R1", "SECP384R1", "SECP521R1"), key="ecc_curve")  # added key
        pubkey, privkey = generate_ecc_key_pair(curve_name)
        if st.button("🔄 Generate ECC key pair", key="generate_ecc"):  # added key
            st.toast("Generating ECC key pair...", icon="🌀")
            time.sleep(1)
            download_key_pair(pubkey, privkey, "ecc")

    with try_container:
        mode = st.selectbox("Mode", ("Sign", "Verify"), key="ecc_mode")  # added key
        key = st.file_uploader(
            "Upload private key" if mode == "Sign" else "Upload public key", type="pem", key="ecc_key_upload"
        )
        input_text = st.text_area("Enter text", height=150, key="ecc_text")
        signature = st.text_area("Paste signature (hex)", height=80, key="ecc_sig") if mode == "Verify" else None

        input_ok = all([key, input_text]) if mode == "Sign" else all([key, input_text, signature])
        st.session_state.ecc_btn_disabled = not input_ok

        if st.button("✨ GO!", disabled=st.session_state.ecc_btn_disabled, key="ecc_go"):  # added key
            try:
                key_data = key.getvalue()
                if mode == "Sign":
                    privkey = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                    output = privkey.sign(input_text.encode(), ec.ECDSA(hashes.SHA256())).hex()
                else:
                    pubkey = serialization.load_pem_public_key(key_data, backend=default_backend())
                    pubkey.verify(bytes.fromhex(signature), input_text.encode(), ec.ECDSA(hashes.SHA256()))
                    output = "✅ Signature is VALID"

                output_container.markdown(f"```\n{output}\n```")
            except Exception as e:
                st.error(f"Error: {e}", icon="🚨")

@st.cache_data
def generate_ecc_key_pair(curve_name: str) -> tuple[bytes, bytes]:
    curve = {"SECP256R1": ec.SECP256R1(), "SECP384R1": ec.SECP384R1(), "SECP521R1": ec.SECP521R1()}[curve_name]
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    return (
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )

# --- DSA ---
def dsa_tab():
    st.subheader("🖋️ DSA Sign & Verify")
    key_container = st.expander("Key pair generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)

    with key_container:
        key_size = st.selectbox("Key size", (1024, 2048, 3072), index=1, key="dsa_keysize")  # added key
        pubkey, privkey = generate_dsa_key_pair(key_size)
        if st.button("🔄 Generate DSA key pair", key="generate_dsa"):  # added key
            st.toast("Generating DSA key pair...", icon="🖋️")
            time.sleep(1)
            download_key_pair(pubkey, privkey, "dsa")

    with try_container:
        mode = st.selectbox("Mode", ("Sign", "Verify"), key="dsa_mode")  # added key
        key = st.file_uploader(
            "Upload private key" if mode == "Sign" else "Upload public key", type="pem", key="dsa_key_upload"
        )
        input_text = st.text_area("Enter text", height=150, key="dsa_text")
        signature = st.text_area("Paste signature (hex)", height=80, key="dsa_sig") if mode == "Verify" else None

        input_ok = all([key, input_text]) if mode == "Sign" else all([key, input_text, signature])
        st.session_state.dsa_btn_disabled = not input_ok

        if st.button("✨ GO!", disabled=st.session_state.dsa_btn_disabled, key="dsa_go"):  # added key
            try:
                key_data = key.getvalue()
                if mode == "Sign":
                    privkey = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                    output = privkey.sign(input_text.encode(), hashes.SHA256()).hex()
                else:
                    pubkey = serialization.load_pem_public_key(key_data, backend=default_backend())
                    pubkey.verify(bytes.fromhex(signature), input_text.encode(), hashes.SHA256())
                    output = "✅ Signature is VALID"

                output_container.markdown(f"```\n{output}\n```")
            except Exception as e:
                st.error(f"Error: {e}", icon="🚨")

@st.cache_data
def generate_dsa_key_pair(size: int) -> tuple[bytes, bytes]:
    private_key = dsa.generate_private_key(key_size=size, backend=default_backend())
    public_key = private_key.public_key()
    return (
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )

# --- Run Interface ---
tab1, tab2, tab3 = st.tabs(["🔐 RSA", "🌀 ECC", "🖋️ DSA"])
with tab1: rsa_tab()
with tab2: ecc_tab()
with tab3: dsa_tab()
