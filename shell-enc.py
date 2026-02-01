# encrypt_shellcode.py
import sys
from Crypto.Cipher import ARC4

key = b"WindowsUpdateAgent2024"
with open("data.bin", "rb") as f:
    shellcode = f.read()

cipher = ARC4.new(key)
encrypted = cipher.encrypt(shellcode)

print("unsigned char encrypted_shellcode[] = {")
for i, byte in enumerate(encrypted):
    if i % 12 == 0:
        print("\n    ", end="")
    print(f"0x{byte:02X}, ", end="")
print("\n};")
print(f"unsigned int shellcode_size = {len(encrypted)};")
