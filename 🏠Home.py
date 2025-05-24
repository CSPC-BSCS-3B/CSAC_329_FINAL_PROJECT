import streamlit as st


st.set_page_config(
    page_title="Applied Cryptography",
    page_icon="🥷🏿",
    layout="wide"
)


def main() -> None:
    st.title("Applied Cryptography")
 
    tab1, tab2, tab3, tab4 = st.tabs(["🏠Home", "🔐Asymmetric", "🔏Symmetric", "🔑Hashing Functions"])

    with tab1:

        col1, col2 = st.columns([6, 1])
        with col1:
            col1_1, col1_2 = st.columns([6, 1])
            with col1_1:
                st.subheader("About this Project")
                st.markdown("""
                This Applied Cryptography Application project aims to develop a simple
                application that implements various cryptographic techniques to secure
                communication, data, and information exchange. Cryptography is the science of
                encoding and decoding messages to protect their confidentiality, integrity,
                and authenticity. This website provides a user-friendly interface that
                allows users to encrypt, decrypt, and hash messages/files using different
                cryptographic algorithms.Whether you're a beginner or an experienced
                cryptographer, this app will help you understand and experience cryptographic
                concepts effectively.\n  
                """)
                
            with col1_2:
                image = st.image("https://raw.githubusercontent.com/CSPC-BSCS-3B/Images_Collection/refs/heads/main/crypto_robot.gif", width=0)


        st.divider()

        col3, col4, col5 = st.columns(3)

        with col3:
            col3.subheader(":green[Member 1]")
            col3.markdown("##### Divino Franco R. Aurellano")
            col3.image("https://raw.githubusercontent.com/CSPC-BSCS-3B/Images_Collection/refs/heads/main/franco_green_border.jpg", width=300)

        with col4:
            col4.subheader(":green[Member 2]")
            col4.markdown("##### Maica S. Romaraog")
            col4.image("https://raw.githubusercontent.com/CSPC-BSCS-3B/Images_Collection/refs/heads/main/maica_green_border.jpg", width=300)

        with col5:
            col5.subheader(":green[Member 3]")
            col5.markdown("##### Lj Tan T. Saldivar")
            col5.image("https://raw.githubusercontent.com/CSPC-BSCS-3B/Images_Collection/refs/heads/main/lj.jpg", width=300)

    with tab2:
        st.header("🔐Asymmetric")
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
        
        **Importance:**        - Enables secure communication over insecure channels
        - Foundation for SSL/TLS, digital signatures, and cryptocurrencies
        """)
        
        st.divider()
        
        st.subheader("Click here to try out the asymmetric algorithms")
        st.page_link(page="pages/🔐Asymmetric_Algorithms.py",
        label=":green[Asymmetric Algorithms]")

    with tab3:
        st.header("🔏Symmetric")
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

        st.subheader("Click here to try out the symmetric algorithms")
        st.page_link(page="pages/🔏Symmetric_Algorithms.py",
        label=":green[Symmetric Algorithms]")

    with tab4:
        st.header("🔑Hashing Functions")
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

        st.subheader("Click here to try out the hashing functions")
        st.page_link(page="pages/🔑Hashing_Functions.py",
        label=":green[Hash Functions]")
        

if __name__ == "__main__":
    main()