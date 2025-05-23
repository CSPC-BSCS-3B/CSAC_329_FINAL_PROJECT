import streamlit as st
import hashlib
import time
from typing import Dict, List, Tuple

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

def calculate_multiple_hashes(data, algorithms: List[str], input_type: str) -> Dict[str, Tuple[str, float]]:
    """Calculate hashes using multiple algorithms and measure performance"""
    results = {}
    
    for algorithm in algorithms:
        start_time = time.time()
        
        if input_type == "Text":
            data_to_hash = data
        else:  # File
            # Reset file pointer to the beginning for each algorithm
            data.seek(0)
            data_to_hash = data
        
        hash_value = calculate_hash(data_to_hash, algorithm, input_type)
        end_time = time.time()
        duration = end_time - start_time
        
        results[algorithm] = (hash_value, duration)
    
    return results

# --- Streamlit UI ---

st.set_page_config(page_title="Hashing Functions", page_icon="🔑")

st.markdown("### <span style=\"color:#00FFA3;\"> Cryptographic Hash Functions </span>", unsafe_allow_html=True)

st.write("""
A cryptographic hash function is an algorithm that takes an arbitrary amount of data input—a credential—and produces a fixed-size string of characters, which is called a hash value (or a message digest). 
This hash value serves as a unique identifier for the input data. Even a small change in the input data will produce a significantly different hash value.
""")
st.info("This page demonstrates hashing for both text and file inputs using various modern algorithms.", icon="ℹ️")

# Create tabs for different modes
tab1, tab2 = st.tabs(["Single Hash Calculator", "Hash Comparison Tool"])

with tab1:
    # --- Input Selection ---
    col1, col2 = st.columns(2)
    with col1:
        hash_algorithm = st.selectbox(
            "Select Hash Algorithm",
            ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"),
            index=3  # Default to sha256
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

with tab2:
    # Hash comparison tool
    st.subheader("Compare Multiple Hash Functions")
    
    comp_input_type = st.radio(
        "Select Input Type",
        ("Text", "File"),
        horizontal=True,
        key="compare_input_type"
    )
    
    algorithms_to_compare = st.multiselect(
        "Select Hash Algorithms to Compare",
        ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"],
        default=["md5", "sha1", "sha256", "sha3_256", "blake2b"]
    )
    
    comp_output = st.empty()
    
    if comp_input_type == "Text":
        comp_text_input = st.text_area("Enter Text to Hash", height=150, key="compare_text_input")
        if st.button("Compare Hash Functions", use_container_width=True, type="primary"):
            if comp_text_input and algorithms_to_compare:
                with st.spinner("Calculating hashes..."):
                    results = calculate_multiple_hashes(comp_text_input, algorithms_to_compare, "Text")
                    
                    # Display results in a table
                    data = []
                    for algo, (hash_value, duration) in results.items():
                        data.append({
                            "Algorithm": algo.upper(),
                            "Hash Value": hash_value,
                            "Digest Size (bits)": len(hash_value) * 4,
                            "Time (ms)": round(duration * 1000, 4)
                        })
                    
                    comp_output.dataframe(data, use_container_width=True)
            else:
                comp_output.warning("Please enter text and select at least one algorithm.", icon="⚠️")
    else:
        comp_file = st.file_uploader("Upload a File to Hash", type=None, key="compare_file_uploader")
        if st.button("Compare Hash Functions", use_container_width=True, type="primary"):
            if comp_file is not None and algorithms_to_compare:
                with st.spinner("Calculating hashes..."):
                    results = calculate_multiple_hashes(comp_file, algorithms_to_compare, "File")
                    
                    # Display results in a table
                    data = []
                    for algo, (hash_value, duration) in results.items():
                        data.append({
                            "Algorithm": algo.upper(),
                            "Hash Value": hash_value,
                            "Digest Size (bits)": len(hash_value) * 4,
                            "Time (ms)": round(duration * 1000, 4)
                        })
                    
                    comp_output.dataframe(data, use_container_width=True)
                    # Reset file pointer
                    comp_file.seek(0)
            else:
                comp_output.warning("Please upload a file and select at least one algorithm.", icon="⚠️")

st.markdown("---")
st.markdown("""
**Common Hash Functions:**
- **MD5 (Message Digest 5):** Produces a 128-bit hash value. It's relatively fast but is no longer considered secure against collisions for critical applications.
- **SHA-1 (Secure Hash Algorithm 1):** Produces a 160-bit hash value. Like MD5, SHA-1 has known vulnerabilities and should be avoided for new security applications.
- **SHA-224/SHA-256/SHA-384/SHA-512:** Part of the SHA-2 family, these produce hash values of 224, 256, 384, and 512 bits respectively. Widely used and considered secure for most applications today.
- **SHA-3 (224/256/384/512):** The newest member of the Secure Hash Algorithm family, offering improved security compared to SHA-2. SHA-3 uses a different internal structure (sponge construction) than previous SHA variants.
- **BLAKE2 (b/s):** A high-performance cryptographic hash function, faster than MD5, SHA-1, SHA-2, and SHA-3, yet at least as secure as SHA-3. BLAKE2b is optimized for 64-bit platforms, while BLAKE2s is optimized for 32-bit platforms.

**Use Cases:**
- Verifying data integrity (e.g., checking if a downloaded file has been corrupted).
- Storing passwords securely (by hashing them before storage).
- Digital signatures (to ensure authenticity and integrity of messages).
- Blockchain technology (to secure transactions and blocks).

**Modern Applications:**
- **Zero-Knowledge Proofs:** Modern hash functions are used in ZKP systems to create commitments without revealing the actual data.
- **Certificate Transparency:** Used in CT logs to ensure security certificates are valid and haven't been maliciously issued.
- **Password Storage:** Modern applications use algorithms like Argon2, bcrypt, and PBKDF2 which are designed specifically for password hashing with key stretching.
- **Content Addressable Storage:** Systems like IPFS use hash functions to create content identifiers.
- **Digital Signatures in Cryptocurrency:** Bitcoin uses SHA-256 while Ethereum uses Keccak-256 (a variant of SHA-3).
""")