# U-Boat
* inspired from German naval tactic `Wolfpack` in ww2  

### Notes :
* the malware target Ukraine by default you can choose other countries from the macro list in header file or create new one if it does not exist .
* It has to be run as Administrator in order to work in the next updates il make it escalate privilege by abusing someo undocumented APIs , the shellcodes has been modified for this task so they get executed from the very beginning.
```diff
- after running this malware the recovery will be impossible
```
![fileHJXYWFO7](https://user-images.githubusercontent.com/60795188/159803974-6ecefce0-dfff-4e08-8e47-81aec04303b1.jpg)

# Malware Stages

## stage 1
* in the first the program will Retrieves your geographical location using GetUserGeoID and compare it with ``UKR`` if the comparation evaluate to TRUE  then it will Set the process as critical and jump to stage 2

#### Note :

- before doing any malicous activity ive used a technique to hide control flow using Exception Handlers , We register an exception handler (structured or vectored) which raises another exception which is passed to the next handler which raises the next exception, and so on. Finally, the sequence of handlers should lead to the procedure that we wanted to hide.
  ```mermaid
  graph TD;
    L1-->L2;
    L2-->L3;
    L3-->ENTRY;
  ```
 - C/C++ Code


    ```asm

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

* the program will Retrieves a handle to Ressources that contain our shellcodes in memory then put them in array of HGLOBAL .

## stage 3

* then it will injecting the first 2 wipers in other processes using Shellcode Injection technique the first 2 shellcodes will not only overwrite the MBR, but goes further: walking through many structures of the filesystem and corrupting all of them, also overwrite individual files with random data using EaseUS Partition Manager Drivers 

## stage 4

* the second wave of the 3 shellcodes that will be injected using Thread-Hijack technique first one of them will iterate through all folders and files residing on local fixed drives and verifying that they are not whitelisted. then compares subkeys located within the wht configuration key to the folder name or file extension , the romanian shellcodes will do same job as the first wave

   ![image](https://user-images.githubusercontent.com/60795188/159538144-169ca69b-d284-4290-94d8-7064ad5552ce.png)
   
* if an error or the injection failed during the injection part the program will inject itself with the shellcodes .
   
## stage 5

* finally the program will self exit meaning the system will crash with error code `CRITICAL_PROCESS_DIED`

# Result

* the combination of fragmentation and wiping and encrypting of required structures and files <br> would be enough to make `recovery almost impossible`.


  ![image](https://user-images.githubusercontent.com/60795188/159540577-d5732896-3db5-4426-a8d3-81d98d61e1c1.png)
* Message shown after rebooting the system

