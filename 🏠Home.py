import streamlit as st


st.set_page_config(
    page_title="Applied Cryptography",
    page_icon="🥷🏿",
    layout="wide"
)


def main() -> None:


    tab1, tab2, tab3, tab4 = st.tabs(["🏠Home", "🔐Asymmetric", "🔐Symmetric", "🔑Hashing Functions"])

    with tab1:
        st.header("🏠Home")
        # st.image("", width=200)
        st.markdown("""
        ### What is Asymmetric Cryptography?
        Asymmetric cryptography, also known as public-key cryptography, uses a pair of keys (public and private) for encryption and decryption. It enables secure communication without sharing secret keys in advance.
        
        **Examples:**
        - RSA
        - ECC (Elliptic Curve Cryptography)
        - DSA (Digital Signature Algorithm)
        
        **How it works:**
        - The public key encrypts data; only the private key can decrypt it.
        - Used for secure key exchange, digital signatures, and authentication.
        
        **Importance:**
        - Enables secure communication over insecure channels
        - Foundation for SSL/TLS, digital signatures, and cryptocurrencies
        """)

    with tab2:
        st.header("🔐Asymmetric")
        # st.image("", width=200)
        st.markdown("""
        ### What is Asymmetric Cryptography?
        Asymmetric cryptography, also known as public-key cryptography, uses a pair of keys (public and private) for encryption and decryption. It enables secure communication without sharing secret keys in advance.
        
        **Examples:**
        - RSA
        - ECC (Elliptic Curve Cryptography)
        - DSA (Digital Signature Algorithm)
        
        **How it works:**
        - The public key encrypts data; only the private key can decrypt it.
        - Used for secure key exchange, digital signatures, and authentication.
        
        **Importance:**
        - Enables secure communication over insecure channels
        - Foundation for SSL/TLS, digital signatures, and cryptocurrencies
        """)

    with tab3:
        st.header("🔐Symmetric")
        # st.image("", width=200)
        st.markdown("""
        ### What is Symmetric Cryptography?
        Symmetric cryptography uses the same key for both encryption and decryption. It is fast and suitable for encrypting large amounts of data.
        
        **Examples:**
        - AES (Advanced Encryption Standard)
        - DES (Data Encryption Standard)
        - 3DES (Triple DES)
        
        **How it works:**
        - The same secret key is shared between sender and receiver.
        - Both parties must keep the key secret.
        
        **Importance:**
        - Efficient for bulk data encryption
        - Used in file encryption, VPNs, and secure storage
        """)

    with tab4:
        st.header("🔑Hashing Functions")
        # st.image("", width=200)
        st.markdown("""
        ### What is a Hashing Function?
        A hashing function transforms input data into a fixed-size string of characters, which is typically a hash value. It is a one-way function and cannot be reversed.
        
        **Examples:**
        - SHA-256
        - SHA-1
        - MD5
        
        **How it works:**
        - Takes input data and produces a unique hash value
        - Even a small change in input produces a very different hash
        
        **Importance:**
        - Ensures data integrity
        - Used in password storage, digital signatures, and data verification
        """)


if __name__ == "__main__":
    main()