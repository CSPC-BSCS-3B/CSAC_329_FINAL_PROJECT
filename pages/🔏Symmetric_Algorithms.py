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
            st.error(f"""
            🔑 Invalid key format
            
            Please provide a valid hexadecimal string with {ALGO_CONFIGS[algo_id]['key_size']*2} characters.
            Example: {get_random_bytes(ALGO_CONFIGS[algo_id]['key_size']).hex()}
            """, icon="🚨")
            return
            
        # Track performance
        start_time = time.time()
        
        # Process the operation
        data = input_text.encode() if operation == "Encrypt" else input_text
        
        if operation == "Encrypt":
            output = encrypt_func(data, key)
            end_time = time.time()
            
            # Show stats
            input_len = len(data)
            output_len = len(output.encode())
            output_container.info(f"""
            📊 **Encryption Statistics**:
            - Original size: {input_len} bytes
            - Encrypted size: {output_len} bytes
            - Encryption ratio: {output_len/input_len:.2f}x
            - Time taken: {(end_time - start_time)*1000:.1f} ms
            """)
        else:
            try:
                # Clean input by removing whitespace
                cleaned_input = input_text.strip()
                output = decrypt_func(cleaned_input, key).decode()
                end_time = time.time()
                
                # Show stats
                input_len = len(cleaned_input.encode())
                output_len = len(output.encode())
                output_container.info(f"""
                📊 **Decryption Statistics**:
                - Encrypted size: {input_len} bytes
                - Decrypted size: {output_len} bytes
                - Compression ratio: {input_len/output_len:.2f}x
                - Time taken: {(end_time - start_time)*1000:.1f} ms
                """)
            except UnicodeDecodeError:
                st.error("""
                🔣 Decryption succeeded but the result is not valid text
                
                This could mean:
                1. The key is incorrect
                2. The encrypted data represents a binary file, not text
                3. The ciphertext has been modified or corrupted
                """, icon="🚨")
                return
            except ValueError as ve:
                if "padding" in str(ve).lower() or "invalid base64" in str(ve).lower():
                    st.error("""
                    🔑 Invalid ciphertext format
                    
                    The input doesn't look like valid base64-encoded ciphertext. Check that:
                    1. You're using the correct encrypted text
                    2. The text hasn't been modified or truncated
                    3. There are no extra spaces or line breaks
                    """, icon="🚨")
                else:
                    st.error(f"Value Error: {str(ve)}", icon="🚨")
                return
                
        # Display result with helpful buttons
        output_container.success("✅ Operation completed successfully")
        output_container.text_area("Result", value=output, height=150)
        
        # Add copy button
        output_container.button(
            "📋 Copy to clipboard", 
            key=f"{algo_id}_{operation.lower()}_copy",
            on_click=lambda: st.session_state.update({f"{algo_id}_clipboard": output})
        )
        
        # Keep the output for later use
        st.session_state[f"{algo_id}_last_output"] = output
        
    except Exception as e:
        error_type = type(e).__name__
        if "padding" in str(e).lower():
            output_container.error(f"""
            🔑 Error: Padding issue detected
            
            This usually means:
            1. The key is incorrect
            2. The input data is corrupted or incomplete
            3. The input is not in the expected format
            
            Technical details: {str(e)}
            """, icon="🚨")
        elif "key" in str(e).lower():
            output_container.error(f"""
            🔑 Error: Key issue detected
            
            Please check:
            1. The key is in correct hexadecimal format
            2. The key has the correct length ({ALGO_CONFIGS[algo_id]['key_size']*2} hex characters)
            
            Technical details: {str(e)}
            """, icon="🚨")
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
            st.error(f"""
            🔑 Invalid key format
            
            Please provide a valid hexadecimal string with {ALGO_CONFIGS[algo_id]['key_size']*2} characters.
            Example: {get_random_bytes(ALGO_CONFIGS[algo_id]['key_size']).hex()}
            """, icon="🚨")
            return
            
        # Reset position of file buffer to start
        if hasattr(upload, 'seek'):
            upload.seek(0)
            
        # Read file with error handling
        try:
            file_bytes = upload.read()
            file_size_kb = len(file_bytes) / 1024
            file_size_mb = file_size_kb / 1024
        except Exception as e:
            st.error(f"""
            📁 Error reading file: {str(e)}
            
            The file may be corrupted or inaccessible.
            """, icon="🚨")
            return
              # Create a header with file details
        size_str = f"{file_size_mb:.2f} MB" if file_size_mb >= 1 else f"{file_size_kb:.1f} KB"
        file_header = f"""
        ## 📁 Processing: {upload.name}
        
        - **Size**: {size_str}
        - **Algorithm**: {ALGO_CONFIGS[algo_id]['name']}
        - **Operation**: {operation}
        """
        output_container.markdown(file_header)
        
        # Show file type if possible
        file_type = upload.type if hasattr(upload, 'type') and upload.type else "Unknown type"
        if file_type != "Unknown type":
            output_container.info(f"**File type**: {file_type}")
        
        # File extension
        file_ext = upload.name.split('.')[-1] if '.' in upload.name else 'unknown'
        
        # Process the operation
        if operation == "Encrypt":
            with st.spinner("Encrypting file..."):
                # Track time for performance metrics
                start_time = time.time()
                result_b64 = encrypt_func(file_bytes, key)
                end_time = time.time()
                
                # Prepare download options
                out_bytes = result_b64.encode()
                out_name = f"enc_{upload.name}.txt"
                
                # Show file information
                enc_size_kb = len(out_bytes) / 1024
                enc_size_mb = enc_size_kb / 1024
                time_taken = end_time - start_time
                
                # Format sizes based on magnitude
                orig_size_str = f"{file_size_mb:.2f} MB" if file_size_mb >= 1 else f"{file_size_kb:.1f} KB"
                enc_size_str = f"{enc_size_mb:.2f} MB" if enc_size_mb >= 1 else f"{enc_size_kb:.1f} KB"
                
                output_container.info(f"""
                📊 **Encryption Statistics**:
                - Original size: {orig_size_str}
                - Encrypted size: {enc_size_str}
                - Encryption ratio: {enc_size_kb/file_size_kb:.2f}x
                - Time taken: {time_taken:.2f} seconds
                - Speed: {(file_size_mb/time_taken):.2f} MB/s
                """)
        else:
            with st.spinner("Decrypting file..."):
                try:
                    # Track time for performance metrics
                    start_time = time.time()
                    
                    # Handle different file types for decryption
                    if file_ext.lower() in ['txt', 'text']:
                        # Try to decode as text first (base64 encoded)
                        try:
                            b64 = file_bytes.decode('utf-8').strip()
                            out_bytes = decrypt_func(b64, key)
                        except UnicodeDecodeError:
                            output_container.error("""
                            📄 The file doesn't contain valid text.
                            
                            For text files containing encrypted data, the content should be valid UTF-8 text
                            with base64-encoded ciphertext.
                            """, icon="🚨")
                            return
                    else:
                        # Try direct binary decryption
                        try:
                            # For binary files, assume the raw bytes are the encrypted data
                            # We need to base64 encode it first to match our decrypt function's expectation
                            b64 = base64.b64encode(file_bytes).decode('utf-8')
                            out_bytes = decrypt_func(b64, key)
                        except Exception as e:
                            # If binary approach fails, try as text
                            try:
                                b64 = file_bytes.decode('utf-8').strip()
                                out_bytes = decrypt_func(b64, key)
                            except Exception:
                                output_container.error(f"""
                                🚨 Unable to decrypt file
                                
                                This file doesn't appear to be a valid encrypted file or the key is incorrect.
                                Error: {str(e)}
                                """, icon="🚨")
                                return
                    
                    end_time = time.time()
                    
                    # Try to guess output filename by removing .txt extension if present
                    out_name = upload.name
                    if out_name.lower().endswith('.txt'):
                        out_name = out_name[:-4]
                    if out_name.startswith('enc_'):
                        out_name = out_name[4:]
                    else:
                        out_name = f"dec_{out_name}"
                    
                    # Show file information
                    dec_size_kb = len(out_bytes) / 1024
                    dec_size_mb = dec_size_kb / 1024
                    time_taken = end_time - start_time
                    
                    # Format sizes based on magnitude
                    enc_size_str = f"{file_size_mb:.2f} MB" if file_size_mb >= 1 else f"{file_size_kb:.1f} KB"
                    dec_size_str = f"{dec_size_mb:.2f} MB" if dec_size_mb >= 1 else f"{dec_size_kb:.1f} KB"
                    
                    output_container.info(f"""
                    📊 **Decryption Statistics**:
                    - Encrypted size: {enc_size_str}
                    - Decrypted size: {dec_size_str}
                    - Compression ratio: {file_size_kb/dec_size_kb:.2f}x
                    - Time taken: {time_taken:.2f} seconds
                    - Speed: {(file_size_mb/time_taken):.2f} MB/s
                    """)
                    
                except Exception as e:
                    if "padding" in str(e).lower():
                        output_container.error(f"""
                        🔑 Decryption failed due to padding errors.
                        
                        This usually happens when:
                        1. The decryption key is incorrect
                        2. The ciphertext has been modified or corrupted
                        3. The file doesn't contain proper encrypted data
                        
                        Detailed error: {str(e)}
                        """, icon="🚨")
                    else:
                        output_container.error(f"Error: {str(e)}", icon="🚨")
                    return
                
        # Display result
        output_container.success("✅ Processing complete!")
        
        # Try to detect and preview the decrypted content if appropriate
        if operation == "Decrypt":
            # Detect file type based on content for better user experience
            detected_type = "unknown"
            
            # Check for common file signatures
            if len(out_bytes) >= 4:
                if out_bytes.startswith(b'%PDF'):
                    detected_type = "pdf"
                    output_container.info("📄 PDF file detected")
                elif out_bytes.startswith(b'\x89PNG'):
                    detected_type = "png"
                    output_container.info("🖼️ PNG image detected")
                elif out_bytes.startswith(b'\xff\xd8\xff'):
                    detected_type = "jpeg"
                    output_container.info("🖼️ JPEG image detected")
                elif out_bytes.startswith(b'PK\x03\x04'):
                    detected_type = "zip"
                    output_container.info("📦 ZIP archive detected")
                elif out_bytes.startswith(b'<!DOCTYPE html') or out_bytes.startswith(b'<html'):
                    detected_type = "html"
                    output_container.info("🌐 HTML file detected")
            
            # Try to preview content for small text files
            if len(out_bytes) < 20000 and detected_type == "unknown":
                try:
                    preview_text = out_bytes.decode('utf-8')
                    
                    # Detect specific text file types
                    if preview_text.startswith('{') and preview_text.strip().endswith('}'):
                        detected_type = "json"
                        output_container.info("📝 JSON file detected")
                    elif preview_text.startswith('<?xml'):
                        detected_type = "xml"
                        output_container.info("📝 XML file detected")
                    else:
                        detected_type = "text"
                        output_container.info("📝 Text file detected")
                    
                    # Show preview
                    if len(preview_text) > 500:
                        preview_text = preview_text[:500] + "... (truncated)"
                    
                    preview_container = output_container.expander("📝 Preview of decrypted content", expanded=True)
                    preview_container.code(preview_text, language=detected_type if detected_type in ["json", "xml", "html"] else None)
                    
                except UnicodeDecodeError:
                    # Binary file, don't preview
                    output_container.info("📁 Binary file detected (no preview available)")
        
        # Add output format options for encryption
        if operation == "Encrypt":
            output_container.markdown("### Download Options")
            download_col1, download_col2 = st.columns(2)
            with download_col1:
                output_container.download_button(
                    "⬇️ Download Result (Text File)", 
                    data=out_bytes, 
                    file_name=out_name,
                    mime="text/plain",
                    help="Download as a text file containing base64-encoded encrypted data. Best for sharing via text channels.",
                    key=f"{algo_id}_download_text"
                )
            with download_col2:
                # Binary format (more compact but not human-readable)
                output_container.download_button(
                    "⬇️ Download Result (Binary File)", 
                    data=base64.b64decode(result_b64),
                    file_name=f"enc_{upload.name}.bin",
                    mime="application/octet-stream",
                    help="Download as a binary file. More compact but can only be shared via binary-safe channels.",
                    key=f"{algo_id}_download_bin"
                )
        else:
            # For decryption, offer the original file with appropriate MIME type
            output_container.markdown("### Download Decrypted File")
            
            # Try to determine appropriate MIME type
            mime_type = "application/octet-stream"  # Default for binary
            if detected_type == "text":
                mime_type = "text/plain"
            elif detected_type == "json":
                mime_type = "application/json"
            elif detected_type == "xml":
                mime_type = "application/xml"
            elif detected_type == "html":
                mime_type = "text/html"
            elif detected_type == "pdf":
                mime_type = "application/pdf"
            elif detected_type in ["png", "jpeg"]:
                mime_type = f"image/{detected_type}"
            
            output_container.download_button(
                "⬇️ Download Decrypted File", 
                data=out_bytes, 
                file_name=out_name,
                mime=mime_type,
                help="Download the decrypted file with original content",
                key=f"{algo_id}_download"
            )
            
    except Exception as e:
        error_type = type(e).__name__
        if "padding" in str(e).lower():
            output_container.error(f"""
            🔑 Error: Padding issue detected
            
            This usually means:
            1. The key is incorrect
            2. The input data is corrupted
            3. The input is not in the expected format
            
            Technical details: {str(e)}
            """, icon="🚨")
        elif "key" in str(e).lower():
            output_container.error(f"""
            🔑 Error: Key issue detected
            
            Please check:
            1. The key is in correct hexadecimal format
            2. The key has the correct length ({ALGO_CONFIGS[algo_id]['key_size']*2} hex characters)
            
            Technical details: {str(e)}
            """, icon="🚨")
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
    key_container = st.expander("🔑 Key generation", expanded=True)
    try_container = st.expander("🧪 Try it yourself!", expanded=True)
    output_container = st.expander("🪄 Output", expanded=True)
    
    # Key generation section
    with key_container:
        st.markdown(f"""
        ### {config['name']} Key Information
        
        - **Key size**: {config['key_size']} bytes = {config['key_bits']} bits
        - **Format**: Hexadecimal string ({config['key_size']*2} characters)
        """)
        key_hex = create_key_generation_section(algo_id, config)
    
    # Operation section
    with try_container:
        # Create two equal-width columns for operation and mode
        col1, col2 = st.columns(2)
        with col1:
            operation = st.radio("Operation", ["Encrypt", "Decrypt"], key=f"{algo_id}_operation")
        with col2:
            mode = st.radio("Mode", ["Text", "File"], horizontal=True, key=f"{algo_id}_mode")
        
        # Add divider after operation/mode selection
        st.divider()
        
        # Add mode-specific instructions
        if mode == "Text":
            if operation == "Encrypt":
                st.info("""
                📝 **Text Encryption Mode**
                
                Enter the text you want to encrypt. The result will be a base64-encoded string that 
                contains both the initialization vector (IV) and the ciphertext.
                
                This string can be shared with someone who has the same key to decrypt it.
                """)
            else:
                st.info("""
                📝 **Text Decryption Mode**
                
                Enter the base64-encoded text you want to decrypt. This should be the complete
                output from a previous encryption operation.
                
                Make sure to:
                - Include the entire string without modifications
                - Use the same key that was used for encryption
                - Paste the text exactly as it was provided
                """)
                
            input_text = st.text_area(
                "Enter text" if operation == "Encrypt" else "Enter base64 ciphertext", 
                height=150, 
                key=f"{algo_id}_text"
            )
            
            # Add character count
            if input_text:
                st.caption(f"Character count: {len(input_text)}")
            
            if key_hex and input_text:
                st.session_state[f'{algo_id}_btn_disabled'] = False
                st.session_state[f'{algo_id}_btn_tooltip'] = None
            else:
                st.session_state[f'{algo_id}_btn_disabled'] = True
                st.session_state[f'{algo_id}_btn_tooltip'] = ":red[Please fill in all required fields.]"
                
            btn_col1, btn_col2 = st.columns([3,1])
            with btn_col1:
                if st.button(
                    f"✨ {'Encrypt' if operation == 'Encrypt' else 'Decrypt'} Text", 
                    disabled=st.session_state[f'{algo_id}_btn_disabled'], 
                    help=st.session_state[f'{algo_id}_btn_tooltip'],
                    use_container_width=True,
                    key=f"{algo_id}_go"
                ):
                    process_text_operation(
                        algo_id, key_hex, input_text, operation, 
                        encrypt_func, decrypt_func, output_container
                    )
            with btn_col2:
                if st.button("❌ Clear", key=f"{algo_id}_clear_text", use_container_width=True):
                    st.session_state[f"{algo_id}_text"] = ""
                    st.experimental_rerun()
                
        else:  # File mode
            if operation == "Encrypt":
                st.info("""
                📁 **File Encryption Mode**
                
                Upload any file to encrypt it. The result will be available in two formats:
                
                1. **Text file**: Contains the base64-encoded encrypted data
                2. **Binary file**: More compact but not human-readable
                
                The text file format is recommended for sharing via text channels.
                """)
            else:
                st.info("""
                📁 **File Decryption Mode**
                
                Upload a file containing encrypted data. This should be either:
                
                1. A text file containing base64-encoded encrypted data (from text mode)
                2. A binary file containing raw encrypted data (from binary mode)
                
                Text files are recommended for most situations.
                """)
                
            # Create a visually enhanced file upload area
            upload_area_col1, upload_area_col2 = st.columns([3, 2])
            
            with upload_area_col1:
                # Custom file upload area with better styling
                st.markdown("""
                <style>
                .upload-area {
                    border: 2px dashed #aaa;
                    border-radius: 10px;
                    padding: 20px;
                    text-align: center;
                    margin-bottom: 10px;
                }
                </style>
                <div class="upload-area">
                    <p>📤 Drag and drop files here</p>
                    <p style="font-size: 12px; color: #666;">or use the uploader below</p>
                </div>
                """, unsafe_allow_html=True)
                
                # File uploader
                upload = st.file_uploader(
                    "Select file to process" if operation == "Encrypt" else "Select encrypted file", 
                    key=f"{algo_id}_file",
                    help="You can upload any file type for encryption. For decryption, upload a text file with base64-encoded data or a binary encrypted file."
                )
            
            with upload_area_col2:
                if upload:
                    # File size calculation
                    file_size_kb = upload.size / 1024 if hasattr(upload, 'size') else 0
                    file_size_mb = file_size_kb / 1024
                    
                    # Determine appropriate size unit
                    if file_size_mb >= 1:
                        file_size_str = f"{file_size_mb:.2f} MB"
                    else:
                        file_size_str = f"{file_size_kb:.1f} KB"
                    
                    # File type detection
                    file_type = upload.type if hasattr(upload, 'type') and upload.type else "Unknown type"
                    
                    # File extension
                    file_ext = upload.name.split('.')[-1] if '.' in upload.name else 'unknown'
                    
                    # Show file information in a nicer format
                    st.markdown("### File Information")
                    st.markdown(f"**Name**: {upload.name}")
                    st.markdown(f"**Size**: {file_size_str}")
                    st.markdown(f"**Type**: {file_type}")
                    
                    # File preview section
                    st.markdown("### Preview")
                    
                    # Try to preview the file content based on type
                    try:
                        # Limit preview to first portion of the file
                        preview_size = min(upload.size, 4096)  # Limit preview to 4KB
                        preview_bytes = upload.getvalue()[:preview_size]
                        
                        # Handle different file types for preview
                        if file_ext.lower() in ['txt', 'csv', 'md', 'json', 'xml', 'html', 'css', 'js', 'py']:
                            # Text file preview
                            try:
                                preview_text = preview_bytes.decode('utf-8')
                                if len(preview_text) > 1000:
                                    preview_text = preview_text[:1000] + "... (truncated)"
                                st.text_area("File Content (Preview)", preview_text, height=100, disabled=True)
                            except UnicodeDecodeError:
                                st.warning("Unable to preview file content as text.")
                        elif file_ext.lower() in ['jpg', 'jpeg', 'png', 'gif', 'bmp']:
                            # Image preview
                            st.image(upload, width=200, caption="Image Preview")
                        elif file_ext.lower() in ['pdf']:
                            st.info("PDF file detected (preview not available)")
                        elif operation == "Decrypt" and file_ext.lower() in ['bin', 'enc']:
                            st.info("Binary encrypted file detected")
                        else:
                            # Binary file - show hex dump preview
                            hex_dump = ' '.join(f'{b:02x}' for b in preview_bytes[:100])
                            if len(preview_bytes) > 100:
                                hex_dump += "..."
                            st.code(f"Hex preview: {hex_dump}", language="text")
                    except Exception as e:
                        st.warning(f"Unable to preview file: {str(e)}")
                        
                    # Show warning for large files
                    if file_size_mb > 10:
                        st.warning(f"""
                        ⚠️ Large file detected ({file_size_str})
                        
                        Processing large files may take some time. The application might 
                        appear unresponsive during encryption/decryption.
                        """)
                else:
                    # Show placeholder when no file is uploaded
                    st.markdown("### File Information")
                    st.info("No file selected. Upload a file to see information and preview.")
            
            # Placeholder for progress tracking
            progress_placeholder = st.empty()
                
            # Enable/disable button based on file upload and key
            if upload and key_hex:
                st.session_state[f'{algo_id}_btn_disabled'] = False
                st.session_state[f'{algo_id}_btn_tooltip'] = None
            else:
                st.session_state[f'{algo_id}_btn_disabled'] = True
                st.session_state[f'{algo_id}_btn_tooltip'] = ":red[Please upload a file and provide a key.]"
                
            # Action buttons
            btn_col1, btn_col2, btn_col3 = st.columns([3, 1, 1])
            with btn_col1:
                process_btn = st.button(
                    f"✨ {'Encrypt' if operation == 'Encrypt' else 'Decrypt'} File", 
                    disabled=st.session_state[f'{algo_id}_btn_disabled'], 
                    help=st.session_state[f'{algo_id}_btn_tooltip'],
                    use_container_width=True,
                    key=f"{algo_id}_file_go"
                )
            with btn_col2:
                clear_btn = st.button("❌ Clear", key=f"{algo_id}_clear_file", use_container_width=True)
            with btn_col3:
                if operation == "Encrypt":
                    # Add sample file download option for testing
                    sample_text = "This is a sample text file for testing encryption."
                    st.download_button(
                        "📝 Sample", 
                        data=sample_text.encode(), 
                        file_name="sample_for_encryption.txt",
                        mime="text/plain",
                        help="Download a sample text file to test encryption",
                        use_container_width=True,
                        key=f"{algo_id}_sample_file"
                    )
                
            # Process file when button is clicked
            if process_btn:
                # Show progress bar for large files
                if hasattr(upload, 'size') and upload.size > 1024*1024:  # Larger than 1MB
                    with progress_placeholder.container():
                        progress_bar = st.progress(0)
                        progress_text = st.empty()
                        
                        progress_text.text("Starting file processing...")
                        progress_bar.progress(10)
                        time.sleep(0.2)
                        
                        progress_text.text("Reading file content...")
                        progress_bar.progress(30)
                        time.sleep(0.2)
                        
                        progress_text.text(f"{'Encrypting' if operation == 'Encrypt' else 'Decrypting'} file...")
                        progress_bar.progress(60)
                        
                        # Call the processing function
                        process_file_operation(
                            algo_id, key_hex, upload, operation, 
                            encrypt_func, decrypt_func, output_container
                        )
                        
                        progress_text.text("Processing complete!")
                        progress_bar.progress(100)
                else:
                    # For smaller files, just process directly
                    process_file_operation(
                        algo_id, key_hex, upload, operation, 
                        encrypt_func, decrypt_func, output_container
                    )
                    
            # Handle clear button
            if clear_btn:
                # This can't directly clear the uploader, but provides user instructions
                st.info("Please reselect your file to continue.")
                # Clear any existing state related to this file
                if f"{algo_id}_file" in st.session_state:
                    st.session_state[f"{algo_id}_file"] = None
                
    # Add an extra section for algorithm details
    help_container = st.expander("ℹ️ Algorithm Details", expanded=False)
    with help_container:
        if algo_id == 'aes':
            st.markdown("""
            ### Advanced Encryption Standard (AES)
            
            AES is a symmetric block cipher chosen by the U.S. government to protect classified information. It is implemented in software and hardware throughout the world to encrypt sensitive data.
            
            **Key features**:
            - Block size: 128 bits (16 bytes)
            - Key sizes: 128, 192, or 256 bits
            - Very fast in both software and hardware
            - Highly secure when implemented correctly
            
            **In this implementation**:
            - We use AES-128 (128-bit key)
            - CBC mode with random IV
            - PKCS#7 padding
            """)
        elif algo_id == 'des':
            st.markdown("""
            ### Data Encryption Standard (DES)
            
            DES is an older symmetric-key algorithm for data encryption. While now considered insecure due to its small key size, it's included here for educational purposes.
            
            **Key features**:
            - Block size: 64 bits (8 bytes)
            - Key size: 56 bits (technically 64 bits with 8 parity bits)
            - Developed in the 1970s
            - No longer considered secure for sensitive information
            
            **In this implementation**:
            - CBC mode with random IV
            - PKCS#7 padding
            
            > ⚠️ **Warning**: DES is not recommended for securing sensitive data due to its small key size.
            """)
        elif algo_id == '3des':
            st.markdown("""
            ### Triple DES (3DES)
            
            3DES applies the DES cipher algorithm three times to each data block, significantly increasing security compared to single DES.
            
            **Key features**:
            - Block size: 64 bits (8 bytes)
            - Key size: 168 bits (technically 192 bits with parity bits)
            - More secure than DES but slower
            - Still used in some legacy systems
            
            **In this implementation**:
            - CBC mode with random IV
            - PKCS#7 padding
            
            > ℹ️ **Note**: While more secure than DES, 3DES is significantly slower than modern algorithms like AES. It's included here primarily for educational purposes.
            """)
        
        st.markdown("""
        ---
        
        ### Mode of Operation
        
        This implementation uses **Cipher Block Chaining (CBC)** mode with a randomly generated initialization vector (IV).
        
        CBC mode provides better security properties compared to ECB mode:
        - Identical plaintext blocks will encrypt to different ciphertext blocks
        - Changes in one block affect all subsequent blocks (avalanche effect)
        - Requires an initialization vector (IV) which is randomly generated
        
        ### Padding
        
        **PKCS#7 padding** is used to ensure the data length is a multiple of the block size.
        """)
        
    # Add a FAQ section for common issues
    faq_container = st.expander("❓ FAQ & Troubleshooting", expanded=False)
    with faq_container:
        st.markdown("""
        ### Frequently Asked Questions
        
        #### General Questions
        
        **Q: What's the difference between text mode and file mode?**  
        A: Text mode is for encrypting/decrypting text messages directly in the browser. File mode allows you to encrypt/decrypt entire files of any type.
        
        **Q: Can I decrypt data that was encrypted with a different algorithm?**  
        A: No, you must use the same algorithm (and key) that was used for encryption.
        
        **Q: Is my data secure when using this tool?**  
        A: Yes, all processing is done in your browser. Your keys and data never leave your computer.
        
        #### Common Errors
        
        **Q: I get a "padding" error when decrypting. What's wrong?**  
        A: This usually means either:
        - You're using the wrong key
        - The ciphertext has been modified or truncated
        - You're trying to decrypt data that wasn't properly encrypted
        
        **Q: The decryption succeeded but shows random characters. What happened?**  
        A: You might be trying to decrypt a binary file in text mode. Try using file mode instead.
        
        **Q: My file is too large to encrypt. What should I do?**  
        A: For very large files, consider:
        - Splitting the file into smaller chunks
        - Using a dedicated encryption tool on your computer
        - Compressing the file before encryption
        
        #### Key Management
        
        **Q: How do I share the key securely with someone else?**  
        A: Never share encryption keys via the same channel as the encrypted data. Use a separate secure channel.
        
        **Q: What if I lose my key?**  
        A: There is no way to recover encrypted data without the original key. Always keep a secure backup of your keys.
        """)
        
        # Add a reset button for when things go wrong
        if st.button("🔄 Reset All", key=f"{algo_id}_reset"):
            # Clear algorithm-specific session state
            for key in list(st.session_state.keys()):
                if key.startswith(algo_id):
                    del st.session_state[key]
            st.experimental_rerun()

# — Main UI Layout —
def aes_tab():
    create_algorithm_tab('aes', ALGO_CONFIGS['aes'], aes_encrypt, aes_decrypt)

def des_tab():
    create_algorithm_tab('des', ALGO_CONFIGS['des'], des_encrypt, des_decrypt)

def triple_des_tab():
    create_algorithm_tab('3des', ALGO_CONFIGS['3des'], triple_des_encrypt, triple_des_decrypt)

# — Streamlit UI —
st.header("🔏 Symmetric Algorithms")

st.markdown("""
Symmetric cryptography uses the **same key** for both encryption and decryption. It's generally faster than asymmetric encryption but requires a secure method to share the key between parties.

This tool allows you to encrypt and decrypt both **text messages** and **files** using industry-standard symmetric algorithms.

### How to use this tool:

\t1. Select an algorithm tab (AES, DES, or 3DES)
\t2. Generate or enter an encryption key
\t3. Choose between Text or File mode
\t4. Enter your text or upload a file
\t5. Click the Process button
\t6. View the results and download if needed

⚠️ **Security Note**: For serious security applications, we recommend using AES, which is the current industry standard.
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
## About Symmetric Encryption

Symmetric encryption uses the same key for both encryption and decryption. It's generally faster than asymmetric encryption but requires a secure method to share the key between parties.

### Algorithms Explained

- **AES (Advanced Encryption Standard)** 🔐  
  The current industry standard, offering excellent security and performance. Supports key sizes of 128, 192, and 256 bits. It's widely used in applications including:
  - Secure communications (HTTPS, VPNs)
  - File encryption
  - Password managers
  - Disk encryption

- **DES (Data Encryption Standard)** 🔒  
  An older algorithm with a 56-bit effective key length, now considered insecure for modern applications. It was the standard encryption algorithm for the U.S. government from 1977 to 2002.

- **3DES (Triple DES)** 🔏  
  Applies the DES algorithm three times to each data block, providing improved security over standard DES. It's a transitional algorithm used in some legacy systems.

### Technical Implementation Details

All implementations on this page use:
- **CBC (Cipher Block Chaining)** mode with a randomly generated initialization vector (IV)
- **PKCS#7 padding** to handle data that isn't a multiple of the block size
- **Base64 encoding** for output to ensure it can be safely stored and transmitted

### Recommended Security Practices

1. **Use AES** for all new applications requiring symmetric encryption
2. **Keep your keys secure** and never share them via the same channel as the encrypted data
3. **Generate random keys** rather than using passwords or memorable phrases
4. **Rotate keys periodically** for long-term secure communications
5. **Consider using authenticated encryption** (not implemented here) for production systems
""")
st.write("🔐 Powered by PyCryptodome | 🛠️ Built for educational purposes")
