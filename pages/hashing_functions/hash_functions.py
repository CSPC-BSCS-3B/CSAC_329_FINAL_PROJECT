import streamlit as st
import hashlib

# --- Hashing Functions ---

def calculate_hash(data, algorithm, input_type):
    """Calculates the hash of the given data using the specified algorithm."""
    hasher = hashlib.new(algorithm)
    
    if input_type == "Text":
        hasher.update(data.encode('utf-8'))
    elif input_type == "File":
        # Read file in chunks to handle large files
        for chunk in iter(lambda: data.read(4096), b""):
            hasher.update(chunk)
            
    return hasher.hexdigest()

# --- Streamlit UI ---

st.set_page_config(page_title="Hashing Functions", page_icon="🔑")

st.markdown("### <span style=\"color:#00FFA3;\"> Cryptographic Hash Functions </span>", unsafe_allow_html=True)

st.write("""
A cryptographic hash function is an algorithm that takes an arbitrary amount of data input—a credential—and produces a fixed-size string of characters, which is called a hash value (or a message digest). 
This hash value serves as a unique identifier for the input data. Even a small change in the input data will produce a significantly different hash value.
""")
st.info("This page demonstrates hashing for both text and file inputs using various algorithms.", icon="ℹ️")

# --- Input Selection ---
col1, col2 = st.columns(2)
with col1:
    hash_algorithm = st.selectbox(
        "Select Hash Algorithm",
        ("md5", "sha1", "sha256", "sha384", "sha512"),
        index=2  # Default to sha256
    )
with col2:
    input_type = st.radio(
        "Select Input Type",
        ("Text", "File"),
        horizontal=True
    )

# --- Data Input ---
output_placeholder = st.empty() # For displaying hash output or errors

if input_type == "Text":
    text_input = st.text_area("Enter Text to Hash", height=150, key="hash_text_input")
    if st.button(f"Hash Text using {hash_algorithm.upper()}", use_container_width=True, type="primary"):
        if text_input:
            with st.spinner(f"Hashing text with {hash_algorithm.upper()}..."):
                hex_digest = calculate_hash(text_input, hash_algorithm, "Text")
                output_placeholder.success(f"**{hash_algorithm.upper()} Hash:** `{hex_digest}`")
        else:
            output_placeholder.warning("Please enter some text to hash.", icon="⚠️")

elif input_type == "File":
    uploaded_file = st.file_uploader("Upload a File to Hash", type=None, key="hash_file_uploader")
    if st.button(f"Hash File using {hash_algorithm.upper()}", use_container_width=True, type="primary"):
        if uploaded_file is not None:
            with st.spinner(f"Hashing file with {hash_algorithm.upper()}..."):
                # To read the file content, we pass the uploaded_file object directly
                hex_digest = calculate_hash(uploaded_file, hash_algorithm, "File")
                output_placeholder.success(f"**{hash_algorithm.upper()} Hash of '{uploaded_file.name}':** `{hex_digest}`")
                # Reset file pointer to allow re-hashing or re-processing if needed
                uploaded_file.seek(0)
        else:
            output_placeholder.warning("Please upload a file to hash.", icon="⚠️")

st.markdown("---")
st.markdown("""
**Common Hash Functions:**
- **MD5 (Message Digest 5):** Produces a 128-bit hash value. It's relatively fast but is no longer considered secure against collisions for critical applications.
- **SHA-1 (Secure Hash Algorithm 1):** Produces a 160-bit hash value. Like MD5, SHA-1 has known vulnerabilities and should be avoided for new security applications.
- **SHA-256 (Secure Hash Algorithm 256-bit):** Part of the SHA-2 family, produces a 256-bit hash. Widely used and considered secure.
- **SHA-384 (Secure Hash Algorithm 384-bit):** Part of the SHA-2 family, produces a 384-bit hash. Offers higher security than SHA-256.
- **SHA-512 (Secure Hash Algorithm 512-bit):** Part of the SHA-2 family, produces a 512-bit hash. Provides a very high level of security.

**Use Cases:**
- Verifying data integrity (e.g., checking if a downloaded file has been corrupted).
- Storing passwords securely (by hashing them before storage).
- Digital signatures (to ensure authenticity and integrity of messages).
- Blockchain technology (to secure transactions and blocks).
""")