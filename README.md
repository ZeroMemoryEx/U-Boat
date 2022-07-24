# U-Boat

![https://user-images.githubusercontent.com/60795188/159803974-6ecefce0-dfff-4e08-8e47-81aec04303b1.jpg](https://user-images.githubusercontent.com/60795188/159803974-6ecefce0-dfff-4e08-8e47-81aec04303b1.jpg)

- the Project inspired from German naval tactic `Wolfpack` in WW2 ,The idea is to attack the target on convoys , the malware contain some shellcodes that created by pro-russian threat actors

### Notes :

- the malware target Ukraine by default you can choose other countries from the macro list in header file or create new one if it does not exist .
- It has to be run as Administrator in order to work in the next updates il make it escalate privilege by abusing some undocumented APIs , the shellcodes has been modified for this task so they get executed from the very beginning.

<p align="center">
  <img src="https://user-images.githubusercontent.com/60795188/180663497-afeb1572-7c32-46dd-acdd-2bfe0e38174b.png" alt="Sublime's custom image"/>
</p>

```
- after running this malware the recovery will be impossible
```

# Malware Stages

## stage 1

- in the first the program will Retrieves your geographical location using GetUserGeoID and compare it with `UKR` if the comparation evaluate to TRUE then it will Set the process as critical using undocumented API RtlSetProcessIsCritical and jump to stage 2

### Note :

- RtlSetProcessIsCritical makes the process critical, any attempt to terminate it will BSOD the system (Blue Screen of Death) , although it can be bypassed easily using NtSetInformationProcess by injecting a DLL into it , i made PoC of it check it out from here [BypassRtlSetProcessIsCritical](https://github.com/ZeroM3m0ry/BypassRtlSetProcessIsCritical)
- 
- before doing any malicious activity ive used a technique to hide control flow using Exception Handlers , We register an exception handler (structured or vectored) which raises another exception which is passed to the next handler which raises the next exception, and so on. Finally, the sequence of handlers should lead to the procedure that we wanted to hide.

```
graph TD;
  L1-->L2;
  L2-->L3;
  L3-->ENTRY;
```

- C/C++ Code

```

void LABEL1()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LABEL2();
    }
}

void LABEL3()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MaliciousEntry();
    }
}

void LABEL2()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LABEL3();
    }
}

```

## stage 2

- the program will Retrieves a handle to Resources that contain our shellcodes in memory then put them in array of HGLOBAL .

## stage 3

- then it will injecting the first 2 wipers in other processes using Process Injection technique the first 2 shellcodes will not only overwrite the MBR, but goes further: walking through many structures of the filesystem and corrupting all of them, also Disable VSS if enabled and overwrite individual files with random data using EaseUS Partition Manager Drivers

### ****TECHNICAL DETAILS****

- ****OpenProcess API****
    
    Opens an existing local process object and return an open handle to the specified process.****
    
    **Parameters**
    
    `[in] dwDesiredAccess`
    
    The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the [process access rights](https://docs.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights).
    
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.
    
    `[in] bInheritHandle`
    
    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    
    `[in] dwProcessId`
    
    The identifier of the local process to be opened.
    
    If the specified process is the System Idle Process (0x00000000), the function fails and the last error code is `ERROR_INVALID_PARAMETER`. If the specified process is the System process or one of the Client Server Run-Time Subsystem (CSRSS) processes, this function fails and the last error code is `ERROR_ACCESS_DENIED` because their access restrictions prevent user-level code from opening them.
    
    If you are using [GetCurrentProcessId](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid) as an argument to this function, consider using [GetCurrentProcess](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess) instead of OpenProcess, for improved performance.
    
- VirtualAllocEx API
    
    Reserves a region of memory within the virtual address space of a specified process, The function initializes the memory it allocates to zero and return the base address of the allocated memory .
    
- WriteProcessMemory API
    
    Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.****
    
- **CreateRemoteThread API**
    
    Creates a thread that runs in the virtual address space of another process and return a handle to the new thread.
    

## stage 4

- the second wave of the 3 shellcodes that will be injected using Thread-Hijack technique first one of them will iterate through all folders and files residing on local fixed drives and verifying that they are not whitelisted. then compares subkeys located within the wht configuration key to the folder name or file extension , the remaining shellcodes will do same job as the first wave

### ****TECHNICAL DETAILS****

- Thread Hijacking is similar to the previous technique but ****instead of creating new remote thread   it hijack an existing one

![https://user-images.githubusercontent.com/60795188/159538144-169ca69b-d284-4290-94d8-7064ad5552ce.png](https://user-images.githubusercontent.com/60795188/159538144-169ca69b-d284-4290-94d8-7064ad5552ce.png)

- if an error or the injection failed during the injection parts the program will trigger KamiKaze Function basically the program will inject itself with the shellcodes then exit continue to know what will happen when the exit function called .

## stage 5

- when the program exit meaning the system will crash with error code `CRITICAL_PROCESS_DIED` cause the process already set to critical .

# Result

- the combination of fragmentation and wiping and encrypting of required structures and files <br> would be enough to make `recovery almost impossible`.
    
    ![https://user-images.githubusercontent.com/60795188/159540577-d5732896-3db5-4426-a8d3-81d98d61e1c1.png](https://user-images.githubusercontent.com/60795188/159540577-d5732896-3db5-4426-a8d3-81d98d61e1c1.png)
    
- Message shown after rebooting the system
