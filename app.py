import streamlit as st
from core import *

def main():
    st.set_page_config(
        page_title="Secure Steganography 2.0",
        page_icon="🛡️",
        layout="centered",
        initial_sidebar_state="expanded"
    )
    
    st.title("🛡️ Secure Data Hiding 2.0")
    st.markdown("""
    ## Military-Grade Data Hiding
    *AES-256-CBC Encryption + LSB Steganography*
    """)
    
    mode = st.sidebar.radio("Operation Mode", ("🔼 Encode", "🔽 Decode"))
    
    if mode == "🔼 Encode":
        st.header("Secure Message Encoding")
        img_file = st.file_uploader("Upload Cover Image", type=["png", "jpg", "jpeg"])
        
        if img_file:
            try:
                file_bytes = np.frombuffer(img_file.read(), np.uint8)
                image = cv2.imdecode(file_bytes, cv2.IMREAD_UNCHANGED)
                if image is None:
                    raise ValueError("Invalid image file")
                
                st.image(image, caption="Cover Image", use_column_width=True)
                
                message = st.text_area("Secret Message", height=150)
                password = st.text_input("Encryption Key", type="password")
                
                if st.button("🚀 Encrypt & Encode"):
                    if not message or not password:
                        st.warning("Please provide both message and password")
                        return
                    
                    with st.spinner("Securing your message..."):
                        encrypted = encrypt_message(message, password)
                        encoded_image = lsb_embed(image, encrypted)
                        cv2.imwrite("secret_image.png", encoded_image)
                        
                    st.success("✅ Message secured successfully!")
                    with open("secret_image.png", "rb") as f:
                        st.download_button(
                            "📥 Download Protected Image",
                            f,
                            "secret_image.png",
                            help="Contains encrypted message hidden in pixel data"
                        )
                        
            except Exception as e:
                st.error(f"⛔ Error: {str(e)}")
    
    elif mode == "🔽 Decode":
        st.header("Secure Message Decoding")
        enc_file = st.file_uploader("Upload Protected Image", type=["png", "jpg", "jpeg"])
        
        if enc_file:
            try:
                file_bytes = np.frombuffer(enc_file.read(), np.uint8)
                image = cv2.imdecode(file_bytes, cv2.IMREAD_UNCHANGED)
                if image is None:
                    raise ValueError("Invalid image file")
                
                st.image(image, caption="Protected Image", use_column_width=True)
                password = st.text_input("Decryption Key", type="password")
                
                if st.button("🔓 Decrypt & Extract"):
                    if not password:
                        st.warning("Please provide the decryption key")
                        return
                    
                    with st.spinner("Decrypting secret message..."):
                        encrypted_data = lsb_extract(image)
                        decrypted = decrypt_message(encrypted_data, password)
                        
                    st.success("🔑 Decrypted Message:")
                    st.code(decrypted, language="text")
                    
            except Exception as e:
                st.error(f"⛔ Error: {str(e)}")

if __name__ == "__main__":
    main()