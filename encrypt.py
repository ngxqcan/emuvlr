import os
import sys
import argparse

# Key mã hóa mặc định (bạn có thể thay đổi tùy ý)
DEFAULT_SECRET_KEY = b"TechnoVerse1208"

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % key_len]
    return bytes(result)

def main():
    parser = argparse.ArgumentParser(description="TechnoVerse EXE to Encrypted Payload (.bin/.dat) Converter")
    parser.add_argument("-i", "--input", default="x64/Release/TechnoVerse.exe", help="Path to input EXE file")
    parser.add_argument("-o", "--output", default="payload.bin", help="Path to output encrypted payload file")
    parser.add_argument("-k", "--key", default=DEFAULT_SECRET_KEY.decode("utf-8"), help="Encryption secret key")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[ERROR] Input file '{args.input}' does not exist!")
        sys.exit(1)
        
    print(f"Reading '{args.input}'...")
    with open(args.input, "rb") as f:
        exe_bytes = f.read()
        
    print(f"Encrypting {len(exe_bytes)} bytes using secret key...")
    key_bytes = args.key.encode("utf-8")
    encrypted_bytes = xor_encrypt_decrypt(exe_bytes, key_bytes)
    
    print(f"Writing encrypted payload to '{args.output}'...")
    with open(args.output, "wb") as f:
        f.write(encrypted_bytes)
        
    print(f"[SUCCESS] Encrypted payload successfully generated: '{args.output}' ({len(encrypted_bytes)} bytes)")
    print(f"Key used: '{args.key}'")

if __name__ == "__main__":
    main()
