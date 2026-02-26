# Shellcode Loader — AV Evasion

A Windows shellcode loader with RC4 encryption and process injection via Early Bird APC.

---

## Files

| File | Description |
|------|-------------|
| `loader.c` | Main loader — RC4 decrypt + APC injection into suspended process |
| `shell-enc.py` | Encrypts raw shellcode with RC4 |
| `generate_loader.py` | Generates complete `loader.c` with shellcode already embedded |
| `dll.c` | DLL payload |
| `dll-sideloading.c` | DLL sideloading technique |

---

## Usage

### 1. Encrypt your shellcode
```bash
python shell-enc.py <shellcode.bin>
```

Copy the output array into `loader.c` inside `encrypted_shellcode[]`.

### 2. Or generate the full loader automatically
```bash
python generate_loader.py <shellcode.bin>
```

Outputs a ready-to-compile `loader.c` with shellcode already embedded.

### 3. Compile

**MinGW:**
```bash
gcc loader.c -o loader.exe
```

**MSVC:**
```bash
cl.exe loader.c /link /OUT:loader.exe
```

### 4. Run
```bash
loader.exe
```

---

## Requirements

- Windows
- Python 3 + `pycryptodome` → `pip install pycryptodome`
- MinGW or MSVC
