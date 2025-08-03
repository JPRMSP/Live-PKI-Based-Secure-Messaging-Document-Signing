import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64

st.set_page_config(page_title="PKI Secure Messaging", layout="wide")
st.title("🔐 Live PKI-Based Secure Messaging & Document Signing")
st.markdown("**Real-time demonstration of Public Key Infrastructure concepts**")

# Initialize session state
if 'private_key' not in st.session_state:
    st.session_state['private_key'] = None
if 'public_key' not in st.session_state:
    st.session_state['public_key'] = None
if 'certificate' not in st.session_state:
    st.session_state['certificate'] = None
if 'ciphertext' not in st.session_state:
    st.session_state['ciphertext'] = None
if 'signature' not in st.session_state:
    st.session_state['signature'] = None

# Function: Generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Function: Create self-signed certificate
def create_self_signed_cert(private_key, public_key, common_name="student.local"):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tamil Nadu"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Chennai"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Student PKI Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        public_key
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    return cert

# Function: Download file button
def download_file_button(label, data, file_name):
    b64 = base64.b64encode(data).decode()
    href = f'<a href="data:file/plain;base64,{b64}" download="{file_name}">{label}</a>'
    st.markdown(href, unsafe_allow_html=True)

# Tabs for features
tabs = st.tabs(["🔑 Key & Certificate Generation", "✉️ Encrypt / Decrypt Message", "🖋 Sign / Verify Message"])

with tabs[0]:
    st.subheader("Step 1: Generate RSA Keys and Certificate")
    if st.button("Generate Keys & Certificate"):
        st.session_state['private_key'], st.session_state['public_key'] = generate_keys()
        st.session_state['certificate'] = create_self_signed_cert(
            st.session_state['private_key'],
            st.session_state['public_key']
        )
        st.success("Keys & Self-Signed Certificate Generated Successfully!")

    if st.session_state['private_key']:
        st.markdown("**Private Key:**")
        private_pem = st.session_state['private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        st.code(private_pem.decode(), language="plaintext")
        download_file_button("📥 Download Private Key", private_pem, "private_key.pem")

        st.markdown("**Public Key:**")
        public_pem = st.session_state['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.code(public_pem.decode(), language="plaintext")
        download_file_button("📥 Download Public Key", public_pem, "public_key.pem")

        st.markdown("**Certificate (X.509):**")
        cert_pem = st.session_state['certificate'].public_bytes(serialization.Encoding.PEM)
        st.code(cert_pem.decode(), language="plaintext")
        download_file_button("📥 Download Certificate", cert_pem, "certificate.pem")

with tabs[1]:
    st.subheader("Step 2: Secure Messaging")
    if st.session_state['public_key']:
        message = st.text_area("Enter message to encrypt")
        if st.button("Encrypt Message"):
            ciphertext = st.session_state['public_key'].encrypt(
                message.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
            st.session_state['ciphertext'] = ciphertext
            st.success("Message Encrypted!")
            st.code(base64.b64encode(ciphertext).decode(), language="plaintext")

    if st.session_state['private_key'] and st.session_state['ciphertext']:
        if st.button("Decrypt Message"):
            plaintext = st.session_state['private_key'].decrypt(
                st.session_state['ciphertext'],
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
            st.success("Message Decrypted!")
            st.write("🔓 Original Message:", plaintext.decode())

with tabs[2]:
    st.subheader("Step 3: Digital Signatures")
    if st.session_state['private_key']:
        sign_message = st.text_area("Enter message to sign")
        if st.button("Sign Message"):
            signature = st.session_state['private_key'].sign(
                sign_message.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            st.session_state['signature'] = signature
            st.success("Message Signed!")
            st.code(base64.b64encode(signature).decode(), language="plaintext")

    verify_message = st.text_area("Enter message to verify")
    signature_input = st.text_area("Paste signature (Base64) to verify")
    if st.button("Verify Signature"):
        try:
            st.session_state['public_key'].verify(
                base64.b64decode(signature_input.encode()),
                verify_message.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            st.success("✅ Signature is VALID")
        except Exception as e:
            st.error("❌ Signature is INVALID")
