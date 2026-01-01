import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# --------------- Global Variables ---------------
MAGIC = b"SFS1"
SALT_LEN = 16
ITERATIONS = 200000


# --------------- Checks ---------------
def is_sha256(s: str) -> bool:
    if not isinstance(s, str):
        return False
    s = s.strip().lower()
    return (
        len(s) == 64
        and all(c in "0123456789abcdef" for c in s)
    )


# --------------- Functions ---------------
def generate_key():
    """Generate a new encryption key"""
    return Fernet.generate_key()


def encrypt_file(input_file, output_file, key):
    """
    Encrypt a file using the provided key
    
    Returns:
        True if successful
        False if failed (invalid key/input file don't exist)
    """
    try:
        cipher = Fernet(key)
    except (ValueError, TypeError):
        return False

    # Read input_file 
    try:
        chunk_size = 1024 ** 2   # 1MB
        with open(input_file, "rb") as f_in:
            with open(output_file, "wb") as f_out:
                # read, encrypt and write out the file continuously
                while True:    
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    
                    # encrypt 1MB chunk
                    enc_chunk = cipher.encrypt(chunk)

                    # write out chunk
                    chunk_len = len(enc_chunk)
                    f_out.write(chunk_len.to_bytes(4, byteorder='big'))
                    f_out.write(enc_chunk)      
        return True
    
    except OSError:
        return False


def decrypt_file(input_file, output_file, key):
    """
    Decrypt a file using the provided key
    
    Returns:
        True if successful
        False if failed (wrong key or corrupted file)
    """
    try:
        cipher = Fernet(key)
    except (ValueError, TypeError):
        return False

    # Read input_file file
    try:
        with open(input_file, "rb") as f_in:
            with open(output_file, 'wb') as f_out:
                while True:
                    # get chunk size
                    size_bytes = f_in.read(4)
                    if not size_bytes:
                        break 

                    #bytes to integer 
                    chunk_len = int.from_bytes(size_bytes, byteorder='big')

                    # read encrypted chunks
                    enc_chunk = f_in.read(chunk_len)
                    if not enc_chunk:
                        break
                    
                    # Check if file can be decrypted with key
                    try:
                        dec_chunk = cipher.decrypt(enc_chunk)
                    except InvalidToken:
                        return False
                    
                    # Write out decrypted chunk
                    f_out.write(dec_chunk)
        return True

    except OSError:
        return False


def save_key(key, filename):
    """
    Save encryption key to a file
    
    Returns:
        True if successful
        False if failed
    """
    try:
        with open(filename, "wb") as file:
            file.write(key)        
    except OSError:
        return False
    return True


def load_key(filename):
    """
    Load encryption key from a file
    
    Returns:
        Key (bytes) if successful
        None if failed
    """
    try:
        with open(filename, "rb") as file:
            key = file.read()
        return key
    except FileNotFoundError:
        return None


def hash_file(filename):
    """
    Generate SHA-256 hash of a file
    
    Returns:
        Hash string (hex) if successful
        None if failed (file not found)
    """
    # Declare SHA-256 hash module
    h = hashlib.sha256()
    chunk = 1024 ** 2   # 1MB

    try:
        with open(filename, "rb") as file:
            while True:
                content = file.read(chunk)
                
                # End loop when no more content to read
                if not content:
                    break

                # Feed chunk into the hash state
                h.update(content)
    
    # Return None if file is not found
    except FileNotFoundError:
        return None

    # Return hex string
    return h.hexdigest()


def verify_file(filename, expected_hash):
    """
    Verify file hasn't been tampered with
    
    Returns:
        True if hash matches
        False if hash doesn't match 
        None if file not found
    """
    # Calculate current hash
    actual_hash = hash_file(filename)
    
    # Check if file exists
    if actual_hash is None:
        return None
    
    # Compare with expected hash
    return actual_hash == expected_hash


def derive_key_from_password(password, salt):
    """
    Generate key given a password and salt
    
    Returns:
        Key (bytes) if succesful 
        None if password is not string
    """
    # Check is password is string
    if not isinstance(password, str):
        return None
    
    # Encode password into utf-8 binary
    pw = password.encode("utf-8")

    # Create hash object given salt
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=200000,
                     )
    
    # Return base64-encoded key
    return base64.urlsafe_b64encode(kdf.derive(pw))


def encrypt_file_password(input_file, output_file, password):
    """
    Encrypt a file using the provided password
    
    Returns:
        True if succesful 
        False if failed (input file does not exist)
    """
    salt = os.urandom(SALT_LEN)
    key = derive_key_from_password(password, salt)

    cipher = Fernet(key)
    
    # Read and encrypt file
    try:
        with open(input_file, "rb") as f_in:
            with open(output_file, 'wb') as f_out:
                # Format header
                f_out.write(MAGIC)
                f_out.write(salt)
                chunk_size = 1024 ** 2   # 1MB

                # Encrypt chunk by chunk
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    
                    # encrypt 1MB chunk
                    enc_chunk = cipher.encrypt(chunk)

                    # write out chunk
                    chunk_len = len(enc_chunk)
                    f_out.write(chunk_len.to_bytes(4, byteorder='big'))
                    f_out.write(enc_chunk)
        return True
    
    except OSError:
        return False
    

def decrypt_file_password(input_file, output_file, password):
    """
    Decrypt a file using the provided password
    
    Returns:
        True if successful
        False if failed (wrong key or corrupted file)
    """
    # Read input file to get magic, salt, and encrypted content
    with open(input_file, "rb") as file:
        in_magic = file.read(4)
        salt = file.read(SALT_LEN)

    # Check if file is SFS1 encrypted
    if  in_magic != MAGIC:
        return False

    # Generate key using salt and password
    key = derive_key_from_password(password, salt)

    try:
        cipher = Fernet(key)
    except (ValueError, TypeError):
        return False
    
    # check if file can be decrypted with key
    try:
        with open(input_file, "rb") as f_in:
            # Skip magic bytes and salt length
            f_in.seek(4 + SALT_LEN)

            with open(output_file, 'wb') as f_out:
                while True:
                    # get chunk size
                    size_bytes = f_in.read(4)
                    if not size_bytes:
                        break 

                    #bytes to integer 
                    chunk_len = int.from_bytes(size_bytes, byteorder='big')

                    # read encrypted chunks
                    enc_chunk = f_in.read(chunk_len)
                    if not enc_chunk:
                        break
                    
                    # Check if file can be decrypted with key
                    try:
                        dec_chunk = cipher.decrypt(enc_chunk)
                        
                        # Write out decrypted chunk
                        f_out.write(dec_chunk)
                    except InvalidToken:
                        return False
                    
        return True
    
    except OSError:
        return False