from stegano.lsb import reveal
import base64
import hashlib

# Decrypt message using base64 + password-derived key
def decrypt_message(encrypted_message, password):
    key = hashlib.sha256(password.encode()).hexdigest()  # Generate key
    encrypted_message = base64.b64decode(encrypted_message).decode()  # Decode base64
    decrypted_message = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encrypted_message))  # Simple XOR decryption
    return base64.b64decode(decrypted_message.encode()).decode()  # Decode final message

# Extract and decrypt message from the image
def decode_image(image_path, password):
    try:
        encrypted_message = reveal(image_path)
        if not encrypted_message:
            print("No hidden message found!")
            return

        message = decrypt_message(encrypted_message, password)

        if message:
            print(f"Hidden Message: {message}")
        else:
            print("Incorrect password!")
    except Exception as e:
        print(f"Error: {e}")

# User input for decoding
if __name__ == "__main__":
    image_path = input("Enter the path to the encoded image: ")
    password = input("Enter the password for decryption: ")

    decode_image(image_path, password)
