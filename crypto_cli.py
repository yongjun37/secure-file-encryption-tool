#!/usr/bin/env python3

from argparse import ArgumentParser
import sys
from pathlib import Path
from getpass import getpass

from crypto import (generate_key, 
                    save_key, 
                    load_key, 
                    encrypt_file, 
                    decrypt_file,
                    hash_file,
                    verify_file,
                    is_sha256,
                    decrypt_file_password,
                    encrypt_file_password)

parser = ArgumentParser(
    description="Secure File Encryption Tool (Fernet-based)"
)

# --------------------- Command Functions ---------------------
def cmd_genkey(args):
    key = generate_key()
    success = save_key(key, args.out)

    if success:
        print("✅ Key generated!")
        sys.exit(0)
    else:
        print(f"❌ Failed to save key to {args.out}")
        sys.exit(2)


def cmd_encrypt(args):
    infile = args.input
    outfile = args.out 
    pwmode = args.password

    if not Path(infile).exists():
        print(f"❌ Input file {infile} not found")
        sys.exit(1)
    
    if pwmode:
        pw1 = getpass("Enter password: ")
        pw2 = getpass("Confirm password: ")
        
        if not pw1 or not pw2:
            print("❌ Password cannot be empty")
            sys.exit(1)

        if pw1 != pw2:
            print("❌ Passwords do not match")
            sys.exit(1)

        success = encrypt_file_password(infile, outfile, pw1)
    else:
        keyfile = args.key

        if not Path(keyfile).exists():
            print(f"❌ Key file {keyfile} not found")
            sys.exit(1)
        
        key = load_key(keyfile)
        if key is None:
            print(f"❌ Failed to load key from {keyfile}")
            sys.exit(1)

        success = encrypt_file(infile, outfile, key)

    if success:
        print(f"✅ File successfully encrypted!")
        print(f"   Input:  {infile}")
        print(f"   Output:  {outfile}")
        sys.exit(0)
    else:
        print("❌ Encryption failed!")
        sys.exit(2)


def cmd_decrypt(args):
    infile = args.input
    outfile = args.out
    pwmode = args.password

    if not Path(infile).exists():
        print(f"❌ Input file {infile} not found")
        sys.exit(1)

    if pwmode:
        pw = getpass("Enter password: ")
        
        if not pw:
            print("❌ Password cannot be empty")
            sys.exit(1)

        mode = "password"
        success = decrypt_file_password(infile, outfile, pw)
    else:
        keyfile = args.key  
        if not Path(keyfile).exists():
            print(f"❌ Key file not found: {keyfile} (run -g to generate key first)")
            sys.exit(1)

        key = load_key(keyfile)
        if key is None:
            print(f"❌ Failed to load key from {keyfile}")
            sys.exit(1)
        
        mode = "key file"
        success = decrypt_file(infile, outfile, key)

    if success:
        print(f"✅ File successfully decrypted!")
        print(f"   Mode:    {mode}")
        print(f"   Input:   {infile}")
        print(f"   Output:  {outfile}")
        sys.exit(0)
    else:
        print(f"❌ Decryption failed")
        print(f"   Possible reasons:")
        print(f"   - Wrong {mode}")
        print(f"   - Corrupted encrypted file")
        if pwmode:
            print("   - Invalid encryption format / not encrypted in password mode")
        sys.exit(2)


def cmd_hash(args):
    file = args.input

    if not Path(file).exists():
        print(f"❌ File {file} not found")
        sys.exit(1)

    digest = hash_file(file)

    if digest is None:
        print("❌ Failed to hash file")
        sys.exit(1)

    print(f"SHA-256: {digest}")
    sys.exit(0)


def cmd_verify(args):
    file = args.input
    expected = args.hash.strip().lower()

    if not Path(file).exists():
        print(f"❌ File {file} not found")
        sys.exit(1)

    if not is_sha256(expected):
        print(f"❌ Invalid SHA-256 hash format")
        sys.exit(1)

    result = verify_file(file, expected)

    if result is None:
        print(f"❌ File {file} not found")  # or "Failed to read file"
        sys.exit(1)
    elif result is True:
        print("✅ File integrity verified")
        sys.exit(0)
    else:
        print("❌ File has been tampered with")
        sys.exit(2)


# --------------------- Parsers ---------------------
def build_parser():
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Subparser for genkey 
    p_gen = sub.add_parser("genkey",
                             help="Generate encryption key and save to a key file")
    p_gen.add_argument("--out", 
                       required=True, 
                       help="Output key file path (e.g. my.key)")  
    p_gen.set_defaults(func=cmd_genkey)

    # Subparser for encrypt 
    p_encrypt = sub.add_parser("encrypt",
                             help="Encrypts input file to output file given a key")
    enc_mode = p_encrypt.add_mutually_exclusive_group(required=True)
    p_encrypt.add_argument('--in', 
                           dest='input',
                           required=True, 
                           help="Input file path")  
    p_encrypt.add_argument("--out",
                           required=True, 
                           help="Output file path")  
    enc_mode.add_argument("--key", 
                       help="Key to encrypt file")  
    enc_mode.add_argument("--password",
                       action="store_true",
                       help="Use password mode")
    p_encrypt.set_defaults(func=cmd_encrypt)

    # Subparser for decrypt
    p_decrypt = sub.add_parser("decrypt",
                             help="Decrypts input file to output file given a key")
    dec_mode = p_decrypt.add_mutually_exclusive_group(required=True)
    p_decrypt.add_argument('--in', 
                           dest='input',
                           required=True, 
                           help="Input file path")  
    p_decrypt.add_argument("--out",
                           required=True, 
                           help="Output file path")  
    dec_mode.add_argument("--key",
                           help="Key to decrypt file") 
    dec_mode.add_argument("--password",
                           action="store_true",
                           help="Use password mode") 
    p_decrypt.set_defaults(func=cmd_decrypt)

    # Subparser for hash
    p_hash = sub.add_parser("hash",
                             help="Returns hash value using SHA-256 given a file")
    p_hash.add_argument('--in', 
                          dest='input',
                          required=True, 
                          help="Input file path") 
    p_hash.set_defaults(func=cmd_hash)

    # Subparser for verify
    p_verify = sub.add_parser("verify",
                             help="Verifies file integrity given a valid SHA-256 hash")
    p_verify.add_argument('--in', 
                          dest='input',
                          required=True, 
                          help="Input file path")
    p_verify.add_argument('--hash', 
                          required=True, 
                          help="Valid SHA-256 hash") 
    p_verify.set_defaults(func=cmd_verify)

    return parser

# --------------------- Main ---------------------
def main():
    p = build_parser()
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()