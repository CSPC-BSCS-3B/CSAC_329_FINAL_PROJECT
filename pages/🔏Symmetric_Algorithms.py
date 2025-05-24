# pages/🔏Symmetric_Algorithms.py
import streamlit as st
from Cryptodome.Cipher import AES, DES, DES3
from Cryptodome.Random import get_random_bytes
import base64
import time
from typing import Tuple, Callable, Dict, Any, Optional

# --- Constants ---
ALGO_CONFIGS = {
    'aes': {
        'name': 'AES',
        'key_size': 16,
        'key_bits': 128,
        'cipher_module': AES,
        'emoji': '🔐',
    },
    'des': {
        'name': 'DES',
        'key_size': 8,
        'key_bits': 64,
        'cipher_module': DES,
        'emoji': '🔒',
    },
    '3des': {
        'name': '3DES',
        'key_size': 24,
        'key_bits': 192,
        'cipher_module': DES3,
        'emoji': '🔏',
    }
}

# --- Session state init ---
for algo in ALGO_CONFIGS.keys():
    if f'{algo}_btn_disabled' not in st.session_state:
        st.session_state[f'{algo}_btn_disabled'] = True
    if f'{algo}_btn_tooltip' not in st.session_state:
        st.session_state[f'{algo}_btn_tooltip'] = ":red[Please fill in all required fields.]"

# --- Padding Helpers ---
def pad(data: bytes, block_size: int) -> bytes:
    """
    Add PKCS#7 padding to the data
    
    Args:
        data: The data to pad
        block_size: The cipher block size
        
    Returns:
        Padded data
    """
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from the data
    
    Args:
        data: The padded data
        
    Returns:
        Unpadded data
    """
    padding_len = data[-1]
    return data[:-padding_len]

# --- Generic Encryption/Decryption Functions ---
def symmetric_encrypt(data: bytes, key: bytes, cipher_module) -> str:
    """
    Generic symmetric encryption function
    
    Args:
        data: The plaintext data to encrypt
        key: The encryption key
        cipher_module: The cipher module to use (AES, DES, or DES3)
        
    Returns:
        Base64-encoded ciphertext with IV prepended
    """
    iv = get_random_bytes(cipher_module.block_size)
    cipher = cipher_module.new(key, cipher_module.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, cipher_module.block_size))
    return base64.b64encode(iv + ct).decode()

def symmetric_decrypt(b64: str, key: bytes, cipher_module) -> bytes:
    """
    Generic symmetric decryption function
    
    Args:
        b64: Base64-encoded ciphertext with IV prepended
        key: The decryption key
        cipher_module: The cipher module to use (AES, DES, or DES3)
        
    Returns:
        Decrypted plaintext
    """
    raw = base64.b64decode(b64)
    iv, ct = raw[:cipher_module.block_size], raw[cipher_module.block_size:]
    cipher = cipher_module.new(key, cipher_module.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))

# --- Algorithm-Specific Functions ---
def aes_encrypt(data: bytes, key: bytes) -> str:
    return symmetric_encrypt(data, key, AES)

def aes_decrypt(b64: str, key: bytes) -> bytes:
    return symmetric_decrypt(b64, key, AES)

def des_encrypt(data: bytes, key: bytes) -> str:
    return symmetric_encrypt(data, key, DES)

def des_decrypt(b64: str, key: bytes) -> bytes:
    return symmetric_decrypt(b64, key, DES)

def triple_des_encrypt(data: bytes, key: bytes) -> str:
    return symmetric_encrypt(data, key, DES3)

def triple_des_decrypt(b64: str, key: bytes) -> bytes:
    return symmetric_decrypt(b64, key, DES3)

# — UI Helper Functions —
def create_key_generation_section(algo_id: str, config: Dict[str, Any]) -> str:
    """
    Create the key generation section for an algorithm tab
    
    Args:
        algo_id: The algorithm ID (aes, des, 3des)
        config: The algorithm configuration
        
    Returns:
        The generated key hex string
    """
    if st.button(f"🔑 Generate {config['name']} Key", key=f"generate_{algo_id}"):
        st.session_state[f"{algo_id}_key"] = get_random_bytes(config['key_size']).hex()
        st.toast(f"Generated new {config['name']} key", icon="🔑")
    
    return st.text_input(
        f"{config['name']} Key (hex, {config['key_size']} bytes = {config['key_bits']} bits)", 
        value=st.session_state.get(f"{algo_id}_key", ""), 
        key=f"{algo_id}_key_input",
        help=f"Enter a valid hex string of length {config['key_size']*2} characters"
    )

def process_text_operation(
    algo_id: str,
    key_hex: str, 
    input_text: str, 
    operation: str,
    encrypt_func: Callable,
    decrypt_func: Callable,
    output_container
) -> None:
    """
    Process a text encryption/decryption operation
    
    Args:
        algo_id: The algorithm ID
        key_hex: The hex key string
        input_text: The input text
        operation: Either "Encrypt" or "Decrypt"
        encrypt_func: The encryption function
        decrypt_func: The decryption function
        output_container: The Streamlit container for output
    """
    try:
        # Validate key
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            st.error("Invalid key format. Please provide a valid hexadecimal string.", icon="🚨")
            return
            
        # Process the operation
        data = input_text.encode() if operation == "Encrypt" else input_text
        
        if operation == "Encrypt":
            output = encrypt_func(data, key)
        else:
            try:
                output = decrypt_func(data, key).decode()
            except UnicodeDecodeError:
                st.error("Decryption succeeded but the result is not valid text. The key might be incorrect.", icon="🚨")
                return
                
        # Display result
        output_container.success("✅ Operation completed successfully")
        output_container.markdown(f"```\n{output}\n```")
        
    except Exception as e:
        error_type = type(e).__name__
        if "padding" in str(e).lower():
            output_container.error(f"Padding error: The input data or key is likely incorrect", icon="🚨")
        elif "key" in str(e).lower():
            output_container.error(f"Key error: {str(e)}", icon="🚨")
        else:
            output_container.error(f"{error_type}: {str(e)}", icon="🚨")

def process_file_operation(
    algo_id: str,
    key_hex: str, 
    upload, 
    operation: str,
    encrypt_func: Callable,
    decrypt_func: Callable,
    output_container
) -> None:
    """
    Process a file encryption/decryption operation
    
    Args:
        algo_id: The algorithm ID
        key_hex: The hex key string
        upload: The uploaded file
        operation: Either "Encrypt" or "Decrypt"
        encrypt_func: The encryption function
        decrypt_func: The decryption function
        output_container: The Streamlit container for output
    """
    try:
        # Validate key
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            st.error("Invalid key format. Please provide a valid hexadecimal string.", icon="🚨")
            return
            
        # Read file
        file_bytes = upload.read()
        
        # Process the operation
        if operation == "Encrypt":
            result_b64 = encrypt_func(file_bytes, key)
            out_bytes = result_b64.encode()
            out_name = f"enc_{upload.name}.txt"
        else:
            try:
                b64 = file_bytes.decode()
                out_bytes = decrypt_func(b64, key)
                out_name = f"dec_{upload.name}"
            except UnicodeDecodeError:
                st.error("The uploaded file doesn't contain valid base64 text for decryption.", icon="🚨")
                return
                
        # Display result
        output_container.success("✅ Processing complete!")
        output_container.download_button(
            "⬇️ Download Result", 
            data=out_bytes, 
            file_name=out_name,
            key=f"{algo_id}_download"
        )
        
    except Exception as e:
        error_type = type(e).__name__
        if "padding" in str(e).lower():
            output_container.error(f"Padding error: The input data or key is likely incorrect", icon="🚨")
        elif "key" in str(e).lower():
            output_container.error(f"Key error: {str(e)}", icon="🚨")
        else:
            output_container.error(f"{error_type}: {str(e)}", icon="🚨")

# — Algorithm Tab Functions —
def create_algorithm_tab(
    algo_id: str, 
    config: Dict[str, Any],
    encrypt_func: Callable,
    decrypt_func: Callable
) -> None:
    """
    Create a tab for a specific encryption algorithm
    
    Args:
        algo_id: The algorithm ID (aes, des, 3des)
        config: The algorithm configuration dictionary
        encrypt_func: The encryption function for this algorithm
        decrypt_func: The decryption function for this algorithm
    """
    st.subheader(f"{config['emoji']} {config['name']} Encryption & Decryption")
    
    # Create sections
    key_container = st.expander("Key generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)
    
    # Key generation section
    with key_container:
        key_hex = create_key_generation_section(algo_id, config)
    
    # Operation section
    with try_container:
        operation = st.radio("Operation", ["Encrypt", "Decrypt"], key=f"{algo_id}_operation")
        mode = st.radio("Mode", ["Text", "File"], horizontal=True, key=f"{algo_id}_mode")
        
        if mode == "Text":
            input_text = st.text_area("Enter text or base64", height=150, key=f"{algo_id}_text")
            
            if key_hex and input_text:
                st.session_state[f'{algo_id}_btn_disabled'] = False
            else:
                st.session_state[f'{algo_id}_btn_disabled'] = True
                
            if st.button("✨ Process", disabled=st.session_state[f'{algo_id}_btn_disabled'], key=f"{algo_id}_go"):
                process_text_operation(
                    algo_id, key_hex, input_text, operation, 
                    encrypt_func, decrypt_func, output_container
                )
        else:  # File mode
            upload = st.file_uploader("Upload file", key=f"{algo_id}_file")
            
            if upload and key_hex:
                st.session_state[f'{algo_id}_btn_disabled'] = False
            else:
                st.session_state[f'{algo_id}_btn_disabled'] = True
                
            if st.button("✨ Process", disabled=st.session_state[f'{algo_id}_btn_disabled'], key=f"{algo_id}_file_go"):
                process_file_operation(
                    algo_id, key_hex, upload, operation, 
                    encrypt_func, decrypt_func, output_container
                )

# — Main UI Layout —
def aes_tab():
    create_algorithm_tab('aes', ALGO_CONFIGS['aes'], aes_encrypt, aes_decrypt)

def des_tab():
    create_algorithm_tab('des', ALGO_CONFIGS['des'], des_encrypt, des_decrypt)

def triple_des_tab():
    create_algorithm_tab('3des', ALGO_CONFIGS['3des'], triple_des_encrypt, triple_des_decrypt)

# — Streamlit UI —
st.set_page_config(page_title="Symmetric Algorithms", page_icon="🔏")
st.header("🔏 Symmetric Encryption")

st.markdown("""
Symmetric cryptography uses the *same* key for encryption and decryption.  
Choose an algorithm, operation, and input mode below.
""")
st.divider()

# --- Run Interface ---
tab1, tab2, tab3 = st.tabs([
    f"{ALGO_CONFIGS['aes']['emoji']} {ALGO_CONFIGS['aes']['name']}", 
    f"{ALGO_CONFIGS['des']['emoji']} {ALGO_CONFIGS['des']['name']}", 
    f"{ALGO_CONFIGS['3des']['emoji']} {ALGO_CONFIGS['3des']['name']}"
])
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
