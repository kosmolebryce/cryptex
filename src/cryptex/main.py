import os
import hashlib
from pathlib import Path

"""
Environment
"""
HOME = Path.home()
APPS_DIR = os.getenv("APPS_DIR")
APPS_DATA_DIR = os.getenv("APPS_DATA_DIR")
CRYPTEX_DIR = os.getenv("CRYPTEX_DIR")
CRYPTEX_DATA_DIR = os.getenv("CRYPTEX_DATA_DIR")
CRYPTEX_ARCHIVE_DIR = os.getenv("CRYPTEX_ARCHIVE_DIR")
CRYPTEX_ORIGINS_DIR = os.getenv("CRYPTEX_ORIGINS_DIR")
PWD = os.getenv("PWD")
if not Path(APPS_DATA_DIR).exists():
    print("Could not locate `~/app_data`.")
    print("Creating it now...")
    print()
    app_data_directory = HOME / "app_data"
    Path.mkdir(app_data_directory, parents=True, exist_ok=True)
if not Path(CRYPTEX_DATA_DIR).exists():
    print("Could not locate `cryptex` data directory.")
    print("Creating it now...")
    print()
    app_data_directory = HOME / "app_data"
    cryptex_data_directory = app_data_directory / "cryptex"
    archive_directory = cryptdex_data_directory / "archive"
    origins_directory = cryptex_data_directory / "origins"
    Path.mkdir(cryptex_data_directory, parents=True, exist_ok=True)
    Path.mkdir(archive_directory)
    Path.mkdir(origins_directory)

def xor_encrypt_decrypt(data, key, is_encryption):
    key_bytes = key if isinstance(key, bytes) else key.encode()  # Ensure key is in bytes
    encrypted_decrypted_bytes = bytearray()
    if is_encryption:
        data = b"HEADER" + data  # Append a known header to the data during encryption
    for i, byte in enumerate(data):
        encrypted_decrypted_bytes.append(byte ^ key_bytes[i % len(key_bytes)])
    if not is_encryption:
        # If decrypting, check the header
        if encrypted_decrypted_bytes[:6] != b"HEADER":
            return None  # Return None if header doesn't match
        return encrypted_decrypted_bytes[6:]  # Return the data without the header
    return bytes(encrypted_decrypted_bytes)

def process_file(input_file_path, output_file_path, passphrase, is_encryption):
    # Generate a key from the passphrase
    key = hashlib.sha256(passphrase.encode()).digest()  # Using SHA-256 hash of the passphrase

    with open(input_file_path, 'rb') as file:
        data = file.read()

    # Encrypt or decrypt the data
    processed_data = xor_encrypt_decrypt(data, key, is_encryption)

    if processed_data is None and not is_encryption:
        print("Decryption failed. Please double-check your key and try again.")
        return

    # Ensure the output directory exists
    output_directory = os.path.dirname(output_file_path)
    if not Path(output_directory).exists():
        os.makedirs(output_directory, exist_ok=True)  # Use makedirs to create all intermediate directories if necessary

    # Write the processed data to a new file
    with open(output_file_path, 'wb') as file:
        file.write(processed_data)

    # Print appropriate completion message
    if is_encryption:
        print('Encryption complete. File saved to:', output_file_path)
    else:
        print('Decryption complete. File saved to:', output_file_path)

def en(input_file_path, passphrase):
    base_name = os.path.basename(input_file_path)
    encrypted_file_name = base_name.replace('.txt', '.crypt') if '.txt' in base_name else base_name + '.crypt'
    output_directory = CRYPTEX_ARCHIVE_DIR
    output_file_path = os.path.join(output_directory, encrypted_file_name)
    process_file(input_file_path, output_file_path, passphrase, is_encryption=True)

def de(input_file_path, passphrase):
    base_name = os.path.basename(input_file_path)
    decrypted_file_name = base_name.replace('.crypt', '.txt') if '.crypt' in base_name else base_name + '.txt'
    output_directory = CRYPTEX_ORIGINS_DIR
    output_file_path = os.path.join(output_directory, decrypted_file_name)
    process_file(input_file_path, output_file_path, passphrase, is_encryption=False)
