# Shellcode Loader - AV Evasion

##  EDUCATIONAL PURPOSE ONLY 

**This project is intended strictly for educational and research purposes to understand cybersecurity concepts, antivirus evasion techniques, and defensive mechanisms. Unauthorized use of this software for malicious purposes is illegal and unethical.**

---

## Overview

This repository contains a Windows shellcode loader designed to demonstrate various antivirus evasion techniques. The project showcases how modern malware attempts to bypass security solutions and is intended to help security researchers, red teamers, and defenders better understand these tactics.

**A detailed technical explanation will be coming soon!**

---

## Features

### Core Functionality
- **RC4 Encryption/Decryption**: Encrypts shellcode using the RC4 stream cipher to evade static signature detection
- **Process Injection**: Injects shellcode into legitimate Windows processes (e.g., `svchost.exe`, `dllhost.exe`)
- **APC Queue Injection**: Uses Asynchronous Procedure Call (APC) injection technique for execution
- **Dynamic Process Selection**: Randomly selects target processes to avoid pattern detection

### Evasion Techniques
1. **Obfuscated Decryption Keys**: Encryption keys are XOR-obfuscated in memory
2. **Random Delays**: Implements timing-based sandbox evasion
3. **Memory Padding**: Adds random padding to memory allocations to evade size-based detection
4. **Suspended Process Creation**: Creates processes in suspended state for safer injection
5. **Alternative XOR Decryption**: Includes fallback XOR decryption with nibble swapping

---

## Repository Contents

- **`loader.c`**: Main shellcode loader with RC4 decryption and process injection capabilities
- **`shell-enc.py`**: Python script to encrypt shellcode using RC4 encryption
- **`README.md`**: This file

---

## How It Works

### 1. Shellcode Preparation
Use the `shell-enc.py` script to encrypt your raw shellcode:

```bash
# Place your raw shellcode in data.bin
python shell-enc.py
```

This outputs encrypted shellcode in C array format that can be inserted into `loader.c`.

### 2. Encryption Process
- Reads raw shellcode from `data.bin`
- Encrypts using RC4 cipher with the key: `WindowsUpdateAgent2024`
- Outputs formatted C array for compilation

### 3. Loader Execution Flow
1. **Random Delay**: Implements anti-sandbox timing delays
2. **Process Selection**: Chooses a target process (svchost.exe, dllhost.exe, etc.)
3. **Process Creation**: Creates the target process in a suspended state
4. **Decryption**: Decrypts shellcode using RC4 with obfuscated key
5. **Memory Allocation**: Allocates memory in the target process with random padding
6. **Injection**: Writes decrypted shellcode to the target process
7. **Execution**: Queues APC and resumes thread to execute shellcode

---

## Building and Usage

### Prerequisites
- Windows development environment
- Visual Studio or MinGW-w64 compiler
- Python 3.x with `pycryptodome` library

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/GlitchHunter1/Shellcode-Loader---AV-Evasion.git
   cd Shellcode-Loader---AV-Evasion
   ```

2. **Install Python dependencies**:
   ```bash
   pip install pycryptodome
   ```

### Compilation

**Using Visual Studio:**
```bash
cl.exe loader.c /link /OUT:loader.exe
```

**Using MinGW:**
```bash
gcc loader.c -o loader.exe -lws2_32
```

### Usage Steps

1. Generate your shellcode (e.g., using msfvenom or similar tools)
2. Save raw shellcode to `data.bin`
3. Run the encryption script:
   ```bash
   python shell-enc.py > encrypted.txt
   ```
4. Copy the encrypted shellcode array into `loader.c` (replace the `encrypted_shellcode[]` array)
5. Compile the loader
6. Execute in a controlled test environment

---

## Technical Details

### Encryption
- **Algorithm**: RC4 (Rivest Cipher 4)
- **Key**: `WindowsUpdateAgent2024` (22 bytes)
- **Key Obfuscation**: XOR with 0x55 in memory

### Injection Technique
- **Method**: Early Bird APC Injection
- **Target**: Suspended Windows processes
- **Memory Protection**: Initially RW, then changed to RX/RWX

### Evasion Mechanisms
- Dynamic process selection from a pool of common Windows processes
- Random timing delays (1-5 seconds)
- Memory allocation with variable padding
- In-memory key deobfuscation
- Multiple fallback options for process creation

---

## Legal Disclaimer

**IMPORTANT**: This software is provided for educational and authorized security research purposes only.

- **Authorized Use**: Security research, penetration testing with permission, educational learning
- **Unauthorized Use**: Deploying against systems without explicit authorization, malicious activities, illegal purposes

The author is not responsible for any misuse or damage caused by this software.

---

## Learning Resources

To better understand the techniques used in this project, consider studying:
- Windows Process Injection Techniques
- RC4 Encryption/Decryption
- APC (Asynchronous Procedure Call) Injection
- Windows API Programming
- Antivirus Detection Mechanisms
- Sandbox Evasion Techniques

---

## Coming Soon

- **Detailed Technical Explanation**: In-depth analysis of each evasion technique
- **Additional Evasion Techniques**: More advanced obfuscation methods
