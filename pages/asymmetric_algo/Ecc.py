import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from io import BytesIO
import zipfile
import time

st.set_page_config(
    page_title="ECC",
    page_icon="🌀",
)

if 'ecc_btn_disabled' not in st.session_state:
    st.session_state.ecc_btn_disabled = True

if 'ecc_btn_tooltip' not in st.session_state:
    st.session_state.ecc_btn_tooltip = ":red[Please fill in all required fields.]"

def main():
    st.markdown("### <span style=\"color:#00FFA3;\"> ECC (Elliptic Curve Cryptography) </span>", unsafe_allow_html=True)

    key_container = st.expander("Key pair generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 **Output**", expanded=True)

    with key_container:
        curve = st.selectbox("Choose a curve", ("SECP256R1", "SECP384R1", "SECP521R1"), index=1)
        pubkey, privkey = generate_ecc_key_pair(curve)

        gen_key_btn = st.button(":green[**Generate a new key pair**]", use_container_width=True,
                                help="This generates a new ECC public and private key.")
        placeholder = st.empty()

        if gen_key_btn:
            with st.spinner("Generating ECC key pair..."):
                msg = st.toast("Generating ECC key pair...", icon="🔄")
                time.sleep(1)
                generate_ecc_key_pair.clear()
                msg.toast("ECC key pair ready!", icon="✅")
                placeholder.empty()

                with placeholder.container():
                    key_pair_download_btn(pubkey, privkey)

    with try_container:
        mode = st.selectbox("MODE", ("Sign", "Verify"))
        key = st.file_uploader(
            "📤 Upload private key :red[*]" if mode == "Sign" else "📤 Upload public key :red[*]", type=(".pem"))
        input_text = st.text_area(
            "Insert text below :red[*]", height=150, key="ecc_input_text", placeholder="Type some magic words.")

        signature = None
        if mode == "Verify":
            signature = st.text_area(
                "Paste signature (hex) :red[*]", height=80, key="ecc_signature", placeholder="Paste signature here.")

        input_fields = (key, input_text) if mode == "Sign" else (key, input_text, signature)
        if all(input_fields) and not st.session_state["ecc_input_text"] == "":
            st.session_state.ecc_btn_disabled = False
            st.session_state.ecc_btn_tooltip = None
        else:
            st.session_state.ecc_btn_disabled = True
            st.session_state.ecc_btn_tooltip = ":red[Please fill in all required fields.]"

        if st.button(
                f"✨ **GO!**",
                use_container_width=True,
                disabled=st.session_state.ecc_btn_disabled,
                help=st.session_state.ecc_btn_tooltip):
            try:
                key_bytes = key.getvalue()
                if mode == "Sign":
                    privkey = load_ecc_key(key_bytes, "private")
                    sig = ecc_sign_text(input_text, privkey)
                    output = sig.hex()
                else:
                    pubkey = load_ecc_key(key_bytes, "public")
                    result = ecc_verify_text(input_text, bytes.fromhex(signature), pubkey)
                    output = "Signature is VALID ✅" if result else "Signature is INVALID ❌"

                output_container.markdown(
                    f"<span style=\"color:#00FFA3\"> {output} </span>", unsafe_allow_html=True)
            except Exception as e:
                st.error(f'An error occurred. {mode} failed. {e}', icon="🚨")

@st.experimental_fragment
def key_pair_download_btn(pubkey_bytes: bytes, privkey_bytes: bytes) -> None:
    pubkey_buffer = BytesIO(pubkey_bytes)
    privkey_buffer = BytesIO(privkey_bytes)

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr('ecc_public_key.pem', pubkey_buffer.getvalue())
        zip_file.writestr('ecc_private_key.pem', privkey_buffer.getvalue())

    st.divider()
    st.download_button(
        label="📁 :orange[Download key pair]",
        data=zip_buffer.getvalue(),
        file_name="ecc_key_pair.zip",
        mime="application/zip",
        use_container_width=True,
        help="Download a zip file of the public and private key in PEM format."
    )

@st.cache_data
def generate_ecc_key_pair(curve_name: str) -> tuple[bytes, bytes]:
    curve = {
        "SECP256R1": ec.SECP256R1(),
        "SECP384R1": ec.SECP384R1(),
        "SECP521R1": ec.SECP521R1()
    }[curve_name]
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public_key, pem_private_key

def load_ecc_key(keyfile: bytes, type: str):
    if type == 'public':
        return serialization.load_pem_public_key(keyfile, backend=default_backend())
    elif type == 'private':
        return serialization.load_pem_private_key(keyfile, password=None, backend=default_backend())

def ecc_sign_text(text: str, private_key) -> bytes:
    message = text.encode()
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def ecc_verify_text(text: str, signature: bytes, public_key) -> bool:
    message = text.encode()
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

if __name__ == "__main__":
    main()