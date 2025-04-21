import streamlit as st # type: ignore
import hashlib
from cryptography.fernet import Fernet


stored_data= {}
failed_attempts = {}
authorized = False



# Initialize session variables
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {user_id: {"encrypted_text": ..., "passkey": ...}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Generate and store a key for encryption
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

fernet = Fernet(st.session_state.fernet_key)

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return fernet.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text):
    return fernet.decrypt(encrypted_text.encode()).decode()

# Login Page
def login_page():
    st.title("🔑 Reauthorization Required")
    username = st.text_input("Enter Admin Username")
    password = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.authorized = True
            st.session_state.failed_attempts.clear()
            st.success("✅ Login successful. You may now retry decryption.")
            st.experimental_rerun()
        else:
            st.error("❌ Invalid credentials.")

# Store Data Function
def store_data(user_id, text, passkey):
    encrypted_text = encrypt_data(text)
    hashed_key = hash_passkey(passkey)
    st.session_state.stored_data[user_id] = {
        "encrypted_text": encrypted_text,
        "passkey": hashed_key
    }
    st.success(f"✅ Data stored securely for user: {user_id}")

# Retrieve Data Function
def retrieve_data(user_id, passkey):
    if user_id not in st.session_state.stored_data:
        st.error("🚫 No data found for this user.")
        return

    attempts = st.session_state.failed_attempts.get(user_id, 0)
    if attempts >= 3:
        st.session_state.authorized = False
        st.warning("🔐 Too many failed attempts! Redirecting to Login Page.")
        st.experimental_rerun()
        return

    hashed_input = hash_passkey(passkey)
    correct_hash = st.session_state.stored_data[user_id]["passkey"]

    if hashed_input == correct_hash:
        decrypted = decrypt_data(st.session_state.stored_data[user_id]["encrypted_text"])
        st.success(f"🔓 Decrypted Data: {decrypted}")
        st.session_state.failed_attempts[user_id] = 0  # Reset attempts
    else:
        st.session_state.failed_attempts[user_id] = attempts + 1
        left = 3 - st.session_state.failed_attempts[user_id]
        st.error(f"❌ Incorrect passkey! Attempts remaining: {left}")
        if left == 0:
            st.warning("🔒 Locking access. Redirecting to Login Page.")
            st.experimental_rerun()

# Streamlit UI
def main():
    if not st.session_state.authorized:
        login_page()
        return

    st.sidebar.title("🛡️ Secure Data System")
    menu = st.sidebar.radio("Menu", ["Home", "Store Data", "Retrieve Data", "Login"])

    if menu == "Home":
        st.title("🏠 Secure Data Encryption System")
        st.write("Encrypt and store your data securely with a private passkey.")

    elif menu == "Store Data":
        st.title("📥 Store Your Data")
        user_id = st.text_input("Enter User ID")
        user_text = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Set a Passkey", type="password")

        if st.button("Encrypt & Store"):
            if user_id and user_text and passkey:
                store_data(user_id, user_text, passkey)
            else:
                st.warning("⚠️ All fields are required.")

    elif menu == "Retrieve Data":
        st.title("🔓 Retrieve Your Encrypted Data")
        user_id = st.text_input("Enter Your User ID")
        passkey = st.text_input("Enter Your Passkey", type="password")

        if st.button("Decrypt Data"):
            if user_id and passkey:
                retrieve_data(user_id, passkey)
            else:
                st.warning("⚠️ Both fields are required.")

    elif menu == "Login":
             login_page()

if __name__ == "__main__":
   main()
















