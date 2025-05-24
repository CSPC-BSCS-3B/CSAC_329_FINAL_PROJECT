import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Page settings
st.set_page_config(page_title="🔐 Symmetric Encryption", page_icon="🔒", layout="centered")
st.title("🔐 Symmetric Encryption & Decryption Playground")

# --- Supported Algorithms Configuration ---
algorithm_options = {
    "AES": {"key_sizes": [16, 24, 32], "iv_size": 16, "block_size": 128},
    "DES": {"key_sizes": [8], "iv_size": 8, "block_size": 64},
    "3DES": {"key_sizes": [16, 24], "iv_size": 8, "block_size": 64}
}

# --- Helper Functions ---
def get_cipher(algorithm, key: bytes, iv: bytes):
    algo_map = {
        "AES": algorithms.AES,
        "DES": algorithms.DES,
        "3DES": algorithms.TripleDES
    }
    return Cipher(algo_map[algorithm](key), modes.CBC(iv), backend=default_backend())

def pad_data(data: bytes, block_size: int) -> bytes:
    padder = padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data: bytes, block_size: int) -> bytes:
    unpadder = padding.PKCS7(block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()

# --- UI Elements ---
with st.form("crypto_form"):
    col1, col2 = st.columns(2)
    with col1:
        algorithm = st.selectbox("🔐 Select Algorithm", list(algorithm_options.keys()))
        operation = st.selectbox("⚙️ Operation", ["Encrypt", "Decrypt"])
    with col2:
        mode = st.selectbox("📥 Mode", ["Text", "File"])
    
    key_input = st.text_input("🔑 Enter Key (hex)", placeholder="e.g. 00112233445566778899aabbccddeeff")
    iv_input = st.text_input("🧾 Enter IV (hex)", placeholder="e.g. aabbccddeeff00998877665544332211")

    data = None
    if mode == "Text":
        user_text = st.text_area("📝 Enter Plaintext or Ciphertext")
        if user_text:
            data = user_text.encode() if operation == "Encrypt" else bytes.fromhex(user_text.strip())
    else:
        uploaded_file = st.file_uploader("📁 Upload File")
        if uploaded_file:
            data = uploaded_file.read()

    submitted = st.form_submit_button("🚀 GO!")

# --- Process the Operation ---
if submitted:
    try:
        config = algorithm_options[algorithm]
        key = bytes.fromhex(key_input.strip())
        iv = bytes.fromhex(iv_input.strip())

        # Validate key and IV
        if len(key) not in config["key_sizes"]:
            st.error(f"❌ Invalid key size for {algorithm}. Must be one of: {[k * 8 for k in config['key_sizes']]} bits.")
        elif len(iv) != config["iv_size"]:
            st.error(f"❌ IV must be {config['iv_size'] * 8} bits ({config['iv_size']} bytes).")
        elif data is None:
            st.error("❌ No input data provided.")
        else:
            cipher = get_cipher(algorithm, key, iv)

            if operation == "Encrypt":
                padded = pad_data(data, config["block_size"])
                encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
                st.success("✅ Encrypted Successfully!")
                st.code(encrypted.hex(), language="text")
                st.download_button("⬇️ Download Encrypted File", encrypted, file_name="encrypted_output.bin")
            else:
                decrypted_padded = cipher.decryptor().update(data) + cipher.decryptor().finalize()
                decrypted = unpad_data(decrypted_padded, config["block_size"])
                try:
                    decoded_text = decrypted.decode()
                    st.success("✅ Decrypted Successfully!")
                    st.code(decoded_text, language="text")
                except UnicodeDecodeError:
                    st.warning("⚠️ Decrypted data is binary. Could not decode to UTF-8 text.")
                    st.download_button("⬇️ Download Decrypted File", decrypted, file_name="decrypted_output.bin")
    except Exception as e:
        st.error(f"🚨 Error: {e}")
