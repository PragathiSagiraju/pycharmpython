import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet
import os

# Ensure directories exist
os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("decrypted_files", exist_ok=True)

# Custom Styling
st.markdown("""
    <style>
        body {
            background-color: #f9f9f9;
            font-family: 'Arial', sans-serif;
        }
        .stButton>button {
            background-color: #007BFF;
            color: black;
            border-radius: 5px;
            border: none;
            padding: 5px 10px;
            font-size: 12px;
            transition: 0.3s;
        }
        .stButton>button:hover {
            background-color: #0056b3;
        }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            border-radius: 5px;
            border: 1px solid #ccc;
            padding: 4px;
            font-size: 12px;
        }
        h1 { text-align: center; font-size: 20px; color: #333; }
        h2 { text-align: center; font-size: 16px; color: #555; }
    </style>
""", unsafe_allow_html=True)

# Function to derive encryption key
def derive_key(user_key):
    if not user_key:
        st.error("⚠️ Secret key cannot be empty!")
        return None
    if len(user_key) > 32:
        st.error("⚠️ Secret key must be 32 characters or less!")
        return None
    user_key = user_key.ljust(32)
    key = hashlib.sha256(user_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

# Function to encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data)

# Function to decrypt data
def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data)

# Function to hash data
def hash_data(data, algorithm="SHA-256"):
    return hashlib.sha256(data).hexdigest() if algorithm == "SHA-256" else hashlib.md5(data).hexdigest()

# UI Header
st.markdown("<h1>🔐 Text & File Encryption</h1>", unsafe_allow_html=True)
st.markdown("<h2>Encrypt, Decrypt, and Hash Your Data</h2>", unsafe_allow_html=True)

# Select Action
action = st.selectbox("Select Action", ["Encrypt", "Decrypt", "Hash", "Encrypt & Hash"])

# Encryption Section
if action == "Encrypt":
    st.subheader("🔒 Enter Text or Upload a File to Encrypt:")
    user_text = st.text_area("Enter your text here:")
    uploaded_file = st.file_uploader("Or upload a file to encrypt", type=["txt", "png", "jpg", "mp4", "mp3", "wav"])
    key_input = st.text_input("Enter Encryption Key (1-32 characters)", type="password")

    if st.button("Encrypt"):
        if not user_text and not uploaded_file:
            st.error("⚠️ Please enter text or upload a file!")
        elif not key_input:
            st.error("⚠️ Please enter an encryption key!")
        else:
            key = derive_key(key_input)
            if key:
                if user_text:
                    encrypted_data = encrypt_data(user_text.encode(), key)
                    st.success("✅ Text encrypted successfully!")
                    st.text_area("🔒 Encrypted Text:", base64.b64encode(encrypted_data).decode())
                elif uploaded_file:
                    file_bytes = uploaded_file.read()
                    encrypted_data = encrypt_data(file_bytes, key)
                    st.success("✅ File encrypted successfully!")
                    st.download_button("⬇️ Download Encrypted File", encrypted_data, file_name=f"{uploaded_file.name}.enc")

# Decryption Section (Now Fixed!)
elif action == "Decrypt":
    st.subheader("🔓 Upload Encrypted File or Enter Encrypted Text to Decrypt:")
    uploaded_file = st.file_uploader("Upload encrypted file", type=["enc"])
    encrypted_text = st.text_area("Or paste encrypted text here:")
    key_input = st.text_input("Enter Decryption Key (1-32 characters)", type="password")

    if st.button("Decrypt"):
        if not uploaded_file and not encrypted_text:
            st.error("⚠️ Please upload an encrypted file or paste encrypted text!")
        elif not key_input:
            st.error("⚠️ Please enter the decryption key!")
        else:
            key = derive_key(key_input)
            if key:
                try:
                    if encrypted_text:
                        decrypted_data = decrypt_data(base64.b64decode(encrypted_text.encode()), key)
                        st.success("✅ Decryption successful!")
                        st.text_area("🔓 Decrypted Text:", decrypted_data.decode())
                    elif uploaded_file:
                        file_bytes = uploaded_file.read()
                        decrypted_data = decrypt_data(file_bytes, key)
                        st.success("✅ File decrypted successfully!")
                        st.download_button("⬇️ Download Decrypted File", decrypted_data, file_name=f"decrypted_{uploaded_file.name.replace('.enc', '')}")
                except:
                    st.error("❌ Decryption failed! Incorrect key or invalid encrypted data.")

# Hashing Section (Now Fixed!)
elif action == "Hash":
    st.subheader("🔑 Enter Text or Upload a File to Generate Hash:")
    user_text = st.text_area("Enter your text here:")
    uploaded_file = st.file_uploader("Or upload a file to hash", type=["txt", "png", "jpg", "mp4", "mp3", "wav"])
    hash_algo = st.selectbox("Choose Hashing Algorithm", ["SHA-256", "MD5"])

    if st.button("Generate Hash"):
        if not user_text and not uploaded_file:
            st.error("⚠️ Please enter text or upload a file!")
        else:
            data = user_text.encode() if user_text else uploaded_file.read()
            hash_value = hash_data(data, hash_algo)
            st.success("✅ Hash generated successfully!")
            st.code(f"🔑 Hash Value ({hash_algo}): {hash_value}", language="plaintext")

# Encrypt & Hash Section (Fixed!)
elif action == "Encrypt & Hash":
    st.subheader("🔒 Enter Text or Upload a File to Encrypt & Hash:")
    user_text = st.text_area("Enter your text here:")
    uploaded_file = st.file_uploader("Or upload a file to encrypt & hash", type=["txt", "png", "jpg", "mp4", "mp3", "wav"])
    key_input = st.text_input("Enter Encryption Key (1-32 characters)", type="password")

    if st.button("Encrypt & Hash"):
        if not user_text and not uploaded_file:
            st.error("⚠️ Please enter text or upload a file!")
        elif not key_input:
            st.error("⚠️ Please enter an encryption key!")
        else:
            key = derive_key(key_input)
            if key:
                if user_text:
                    encrypted_data = encrypt_data(user_text.encode(), key)
                    hash_value = hash_data(encrypted_data, "SHA-256")
                    st.success("✅ Text encrypted & hashed successfully!")
                    st.text_area("🔒 Encrypted Text:", base64.b64encode(encrypted_data).decode())
                    st.code(f"🔑 Hash Value (SHA-256): {hash_value}", language="plaintext")
