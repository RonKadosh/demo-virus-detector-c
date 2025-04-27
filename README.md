# Virus Signature Detection and Neutralization Tool

## Overview
This project is a simple virus detection and neutralization tool written in C.  
It reads a binary file containing virus signatures, scans suspect binary files for known signatures, and neutralizes detected viruses by overwriting their code.

## Features
- Load virus signatures from a file (with `"VIRB"`/`"VIRL"` magic number validation).
- Scan files for known virus signatures.
- Print detailed virus signature information.
- Neutralize detected viruses by overwriting with a `RET` (`0xC3`) instruction.
- User-friendly text menu.
- Manual memory management and low-level file I/O.

## Technologies
- Language: C
- Memory: Manual malloc/free.
- I/O: File handling using `fopen`, `fread`, `fwrite`, `fseek`.

## How to Compile
```bash
make
```

## How to Run
```
./virus_detector
```
Follow the on-screen menu instructions.

## Notes
- This is a basic educational implementation and does not provide full real-world antivirus protection.
- Developed as part of the System Programming Extended Lab course at BGU.
