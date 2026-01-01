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
        with open(input_file, "rb") as file:
            raw = file.read()
    except OSError:
        return False
    
    # Encrypt file
    encrypted = cipher.encrypt(raw)

    # Write encrypted code into output_file
    with open(output_file, "wb") as file:
        file.write(encrypted)
        return True


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
        with open(input_file, "rb") as file:
            encrypted = file.read()
    except OSError:
        return False
    
    # Check if file can be decrypted with key
    try:
        decrypted = cipher.decrypt(encrypted)
    except InvalidToken:
        return False
    
    # Write decrypted file into output_file
    with open(output_file, "wb") as file:
        file.write(decrypted)
        return True


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
        with open(input_file, "rb") as file:
            raw = file.read()
    except OSError:
        return False
    
    encrypted = cipher.encrypt(raw)

    # Write encrypted text into output
    try:
        with open(output_file, "wb") as file:
            file.write(MAGIC)
            file.write(salt)
            file.write(encrypted)
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
        encrypted = file.read()

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
        decrypted = cipher.decrypt(encrypted)
    except InvalidToken:
        return False

    # Write file into output
    try:
        with open(output_file, "wb") as file:
            file.write(decrypted)
            return True
    except OSError:
        return False