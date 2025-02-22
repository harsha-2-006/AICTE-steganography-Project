from stegano.lsb import hide
import base64
import hashlib

# Encrypt message using base64 + password-derived key
def encrypt_message(message, password):
    key = hashlib.sha256(password.encode()).hexdigest()  # Generate key
    encoded_message = base64.b64encode(message.encode()).decode()  # Base64 encode
    encrypted_message = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encoded_message))  # Simple XOR encryption
    return base64.b64encode(encrypted_message.encode()).decode()  # Encode final message

# Hide encrypted message in the image
def encode_image(image_path, message, password, output_path):
    encrypted_message = encrypt_message(message, password)
    secret_image = hide(image_path, encrypted_message)
    secret_image.save(output_path)
    print(f"Message successfully encoded into {output_path}")

# User input for encoding
if __name__ == "__main__":
    image_path = input("Enter the path to the image (jpg format): ")
    message = input("Enter the secret message: ")
    password = input("Enter the password for encryption: ")
    output_path = "encoded_image.png"

    encode_image(image_path, message, password, output_path)
