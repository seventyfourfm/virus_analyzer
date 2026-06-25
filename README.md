# malware-analysis

A simple Python tool I built to quickly figure out what a suspicious .exe file does - without actually running it. 

## What it does

You feed it an .exe file, it tells you:
- Basic stuff (hashes, size, when it was compiled)
- What's inside each section (and if any look packed/encrypted)
- What Windows APIs it uses (the shady ones get flagged)
- Any interesting strings (URLs, IPs, passwords, registry keys)
- A peek at the assembly code where the program starts
- A risk score based on what it finds

## Why I made this

bored + interesting project

## Getting it running

You need Python installed. Then open CMD:

```bash
# Go to your desktop (or wherever you work from)
cd C:\Users\YourName\Desktop

# Make a folder for this project
mkdir malware-analysis
cd malware-analysis

# Grab the code
git clone https://github.com/seventyfourfm/malware-analysis.git
cd malware-analysis

# Set up a virtual environment so you don't mess up your Python install
python -m venv venv
venv\Scripts\activate

# You should see (venv) in your terminal now

# Install the two things this needs
pip install pefile capstone

# Done. Copy your suspicious file into this folder and run:
python analyzer.py your_file.exe

#If you already have the files
cd C:\Users\YourName\Desktop\malware-analysis
python -m venv venv
venv\Scripts\activate
pip install pefile capstone
python analyzer.py srs.exe
```

### Example output
```
======================================================================
  MALWARE ANALYZER v2 - Auto-Save Enabled
======================================================================

[*] Target: srs.exe
[*] Time: 2026-06-25 15:16:00
[*] Report: reports\analysis_srs_20260625_151600.txt


======================================================================
  BASIC FILE INFORMATION
======================================================================
  Filename:          srs.exe
  File Size:         24,185,400 bytes (23618.6 KB)
  MD5:              a51b94cba64385eda58e2e84f45b8283
  SHA1:             52f8fe8080cfd46d1714d4ba820c5476204b61ac
  SHA256:           45d323ebcd572ce662cc7a156cef0e883ed5f60d1d97a78457d1d9a568b06698
  Type:              PE Executable
  Machine:           0x8664
  Compiled:          1780070348
  Entry Point RVA:   0xdfc0
  Image Base:        0x140000000
  Entry Point VA:    0x14000dfc0
  Sections:          7
  Architecture:      x64

======================================================================
  SECTION ANALYSIS
======================================================================
  Name       VirtSize   RawSize    Entropy  Perms    Flags
  -----------------------------------------------------------------
  .text      181392     181760     6.465    XR       
  .rdata     80744      80896      5.753    R        
  .data      20656      3584       1.816    RW       
  .pdata     9228       9728       5.315    R        
  .fptable   256        512        0.000    RW       
  .rsrc      62492      62976      7.555    R        [HIGH ENTROPY] 
  .reloc     1908       2048       5.264    R        

======================================================================
  IMPORT ANALYSIS
======================================================================
  Total imports: 145

  [Anti-Debug] (1 found)
    - KERNEL32.dll!IsDebuggerPresent

  [File Ops] (2 found)
    - KERNEL32.dll!ReadFile
    - KERNEL32.dll!WriteFile

======================================================================
  STRING ANALYSIS (Top 30 Interesting)
======================================================================
   1. [Creds, IP]
            <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144cc

   2. [MemAPI]
      VirtualProtect

   3. [Binary]
      mscoree.dll

   4. [Binary]
      bapi-ms-win-core-libraryloader-l1-1-0.dll

   5. [Binary]
      bapi-ms-win-core-string-l1-1-0.dll

   6. [Binary]
      bapi-ms-win-core-timezone-l1-1-0.dll

   7. [Binary]
      bapi-ms-win-core-namedpipe-l1-1-0.dll

   8. [Binary]
      bVCRUNTIME140_1.dll

   9. [Binary]
      bapi-ms-win-core-memory-l1-1-0.dll

  10. [Creds]
      LkEy

  11. [Binary]
      bucrtbase.dll

  12. [Binary]
      bapi-ms-win-core-profile-l1-1-0.dll

  13. [Binary]
      bapi-ms-win-core-sysinfo-l1-1-0.dll

  14. [Binary]
      %s%c%s.exe

  15. [ProcAPI]
      Tcl_CreateThread

  16. [Binary]
      blibcrypto-3.dll

  17. [Binary]
      bpython314.dll

  18. [Mutex]
      Tcl_MutexFinalize

  19. [Binary]
      bapi-ms-win-core-file-l1-2-0.dll

  20. [IP]
      3.0.4.2

  21. [Creds]
      secrets)

  22. [Binary]
      :python314.dll

  23. [Creds]
      setuptools.monkey)

  24. [Binary]
      bapi-ms-win-crt-heap-l1-1-0.dll

  25. [Binary]
      bpywin32_system32\pywintypes314.dll

  26. [Creds]
      _pyrepl.keymap)

  27. [Binary]
      GDI32.dll

  28. [FileAPI]
      ReadFile

  29. [Binary]
      bapi-ms-win-crt-math-l1-1-0.dll

  30. [Binary]
      bapi-ms-win-crt-filesystem-l1-1-0.dll


======================================================================
  DISASSEMBLY AT ENTRY POINT (30 instructions)
======================================================================
  0x14000d3c0 | 48 83 ec 28              | sub      rsp, 0x28           
  0x14000d3c4 | e8 57 02 00 00           | call     0xd620              
  0x14000d3c9 | 48 83 c4 28              | add      rsp, 0x28           
  0x14000d3cd | e9 7a fe ff ff           | jmp      0xd24c              
  0x14000d3d2 | cc                       | int3                         
  0x14000d3d3 | cc                       | int3                         
  0x14000d3d4 | cc                       | int3                         
  0x14000d3d5 | cc                       | int3                         
  0x14000d3d6 | cc                       | int3                         
  0x14000d3d7 | cc                       | int3                         
  0x14000d3d8 | cc                       | int3                         
  0x14000d3d9 | cc                       | int3                         
  0x14000d3da | cc                       | int3                         
  0x14000d3db | cc                       | int3                         
  0x14000d3dc | cc                       | int3                         
  0x14000d3dd | cc                       | int3                         
  0x14000d3de | cc                       | int3                         
  0x14000d3df | cc                       | int3                         
  0x14000d3e0 | 48 83 ec 28              | sub      rsp, 0x28           
  0x14000d3e4 | e8 db 08 00 00           | call     0xdcc4              
  0x14000d3e9 | 85 c0                    | test     eax, eax            
  0x14000d3eb | 74 21                    | je       0xd40e              
  0x14000d3ed | 65 48 8b 04 25 30 00 00 00 | mov      rax, qword ptr gs:[0x30]
  0x14000d3f6 | 48 8b 48 08              | mov      rcx, qword ptr [rax + 8]
  0x14000d3fa | eb 05                    | jmp      0xd401              
  0x14000d3fc | 48 3b c8                 | cmp      rcx, rax            
  0x14000d3ff | 74 14                    | je       0xd415              
  0x14000d401 | 33 c0                    | xor      eax, eax            
  0x14000d403 | f0 48 0f b1 0d 2c 83 03 00 | lock cmpxchg qword ptr [rip + 0x3832c], rcx
  0x14000d40c | 75 ee                    | jne      0xd3fc              

======================================================================
  MALWARE INDICATORS
======================================================================
  [INFO] Anti-analysis: ida
  [HIGH] High entropy in .rsrc: 7.55
  [CRITICAL] Multiple MZ headers (363) - possible binder/dropper

  --------------------------------------------------
  RISK SCORE: 48/100
  [!!] HIGH RISK - Suspicious file

======================================================================
  Analysis Complete!
======================================================================
```
