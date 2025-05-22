import streamlit as st
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from io import BytesIO
import zipfile
import base64

st.set_page_config(
    page_title="Diffie-Hellman",
    page_icon="🔗",
)

def main():
    st.markdown("### <span style=\"color:#00FFA3;\"> Diffie-Hellman Key Exchange </span>", unsafe_allow_html=True)

    param_container = st.expander("Parameter & Key Generation", expanded=True)
    exchange_container = st.expander("Key Exchange", expanded=True)
    output_container = st.expander("🪄 **Output**", expanded=True)

    with param_container:
        key_size = st.selectbox("Choose key size (bits)", (2048, 3072), index=0)
        if st.button("🔑 Generate DH Parameters & Key Pairs", use_container_width=True):
            parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
            private_key_a = parameters.generate_private_key()
            private_key_b = parameters.generate_private_key()
            public_key_a = private_key_a.public_key()
            public_key_b = private_key_b.public_key()

            # Serialize keys for download
            pem_params = parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            pem_priv_a = private_key_a.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pem_pub_a = public_key_a.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pem_priv_b = private_key_b.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pem_pub_b = public_key_b.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Download buttons
            st.download_button("⬇️ Download DH Parameters", pem_params, "dh_parameters.pem")
            st.download_button("⬇️ Download User A Private Key", pem_priv_a, "userA_private.pem")
            st.download_button("⬇️ Download User A Public Key", pem_pub_a, "userA_public.pem")
            st.download_button("⬇️ Download User B Private Key", pem_priv_b, "userB_private.pem")
            st.download_button("⬇️ Download User B Public Key", pem_pub_b, "userB_public.pem")

            st.info("Keys and parameters generated! Download and use them in the next section.")

    with exchange_container:
        st.write("Upload DH parameters and keys for both users to compute the shared secret.")
        param_file = st.file_uploader("📤 Upload DH Parameters (.pem)", type=["pem"], key="params")
        priv_file = st.file_uploader("📤 Upload Your Private Key (.pem)", type=["pem"], key="priv")
        peer_pub_file = st.file_uploader("📤 Upload Peer Public Key (.pem)", type=["pem"], key="peerpub")

        if param_file and priv_file and peer_pub_file:
            if st.button("🔐 Compute Shared Secret", use_container_width=True):
                try:
                    parameters = serialization.load_pem_parameters(param_file.read(), backend=default_backend())
                    private_key = serialization.load_pem_private_key(priv_file.read(), password=None, backend=default_backend())
                    peer_public_key = serialization.load_pem_public_key(peer_pub_file.read(), backend=default_backend())

                    shared_key = private_key.exchange(peer_public_key)
                    # Derive a key for demonstration (using HKDF)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'dh key exchange',
                        backend=default_backend()
                    ).derive(shared_key)
                    output_container.markdown(
                        f"**Shared secret (base64):**<br><span style='color:#00FFA3'>{base64.b64encode(derived_key).decode()}</span>",
                        unsafe_allow_html=True
                    )
                except Exception as e:
                    st.error(f"Error computing shared secret: {e}")

if __name__ == "__main__":
    main()