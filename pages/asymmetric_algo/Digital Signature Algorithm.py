import streamlit as st
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from io import BytesIO
import zipfile
import time

st.set_page_config(
    page_title="DSA",
    page_icon="🖋️",
)

if 'dsa_btn_disabled' not in st.session_state:
    st.session_state.dsa_btn_disabled = True

if 'dsa_btn_tooltip' not in st.session_state:
    st.session_state.dsa_btn_tooltip = ":red[Please fill in all required fields.]"

def main():
    st.markdown("### <span style=\"color:#00FFA3;\"> DSA (Digital Signature Algorithm) </span>", unsafe_allow_html=True)

    key_container = st.expander("Key pair generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 **Output**", expanded=True)

    with key_container:
        key_size = st.selectbox("Choose key size (bits)", (1024, 2048, 3072), index=1)
        pubkey, privkey = generate_dsa_key_pair(key_size)

        gen_key_btn = st.button(":green[**Generate a new key pair**]", use_container_width=True,
                                help="This generates a new DSA public and private key.")
        placeholder = st.empty()

        if gen_key_btn:
            with st.spinner("Generating DSA key pair..."):
                msg = st.toast("Generating DSA key pair...", icon="🔄")
                time.sleep(1)
                generate_dsa_key_pair.clear()
                msg.toast("DSA key pair ready!", icon="✅")
                placeholder.empty()

                with placeholder.container():
                    key_pair_download_btn(pubkey, privkey)

    with try_container:
        mode = st.selectbox("MODE", ("Sign", "Verify"))
        key = st.file_uploader(
            "📤 Upload private key :red[*]" if mode == "Sign" else "📤 Upload public key :red[*]", type=(".pem"))
        input_text = st.text_area(
            "Insert text below :red[*]", height=150, key="dsa_input_text", placeholder="Type some magic words.")

        signature = None
        if mode == "Verify":
            signature = st.text_area(
                "Paste signature (hex) :red[*]", height=80, key="dsa_signature", placeholder="Paste signature here.")

        input_fields = (key, input_text) if mode == "Sign" else (key, input_text, signature)
        if all(input_fields) and not st.session_state["dsa_input_text"] == "":
            st.session_state.dsa_btn_disabled = False
            st.session_state.dsa_btn_tooltip = None
        else:
            st.session_state.dsa_btn_disabled = True
            st.session_state.dsa_btn_tooltip = ":red[Please fill in all required fields.]"

        if st.button(
                f"✨ **GO!**",
                use_container_width=True,
                disabled=st.session_state.dsa_btn_disabled,
                help=st.session_state.dsa_btn_tooltip):
            try:
                key_bytes = key.getvalue()
                if mode == "Sign":
                    privkey = load_dsa_key(key_bytes, "private")
                    sig = dsa_sign_text(input_text, privkey)
                    output = sig.hex()
                else:
                    pubkey = load_dsa_key(key_bytes, "public")
                    result = dsa_verify_text(input_text, bytes.fromhex(signature), pubkey)
                    output = "Signature is VALID ✅" if result else "Signature is INVALID ❌"

                output_container.markdown(
                    f"<span style=\"color:#00FFA3\"> {output} </span>", unsafe_allow_html=True)
            except Exception as e:
                st.error(f'An error occurred. {mode} failed. {e}', icon="🚨")

@st.fragment
def key_pair_download_btn(pubkey_bytes: bytes, privkey_bytes: bytes) -> None:
    pubkey_buffer = BytesIO(pubkey_bytes)
    privkey_buffer = BytesIO(privkey_bytes)

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr('dsa_public_key.pem', pubkey_buffer.getvalue())
        zip_file.writestr('dsa_private_key.pem', privkey_buffer.getvalue())

    st.divider()
    st.download_button(
        label="📁 :orange[Download key pair]",
        data=zip_buffer.getvalue(),
        file_name="dsa_key_pair.zip",
        mime="application/zip",
        use_container_width=True,
        help="Download a zip file of the public and private key in PEM format."
    )

@st.cache_data
def generate_dsa_key_pair(size: int) -> tuple[bytes, bytes]:
    private_key = dsa.generate_private_key(
        key_size=size,
        backend=default_backend()
    )
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

def load_dsa_key(keyfile: bytes, type: str):
    if type == 'public':
        return serialization.load_pem_public_key(keyfile, backend=default_backend())
    elif type == 'private':
        return serialization.load_pem_private_key(keyfile, password=None, backend=default_backend())

def dsa_sign_text(text: str, private_key) -> bytes:
    message = text.encode()
    signature = private_key.sign(
        message,
        hashes.SHA256()
    )
    return signature

def dsa_verify_text(text: str, signature: bytes, public_key) -> bool:
    message = text.encode()
    try:
        public_key.verify(signature, message, hashes.SHA256())
        return True
    except Exception:
        return False

if __name__ == "__main__":
    main()