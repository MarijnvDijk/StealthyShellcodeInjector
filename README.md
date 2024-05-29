# StealthyShellcodeInjector
## Overview
This project implements a stealthy shellcode injector designed to evade detection and perform covert operations within a Windows environment. The injector utilizes several advanced techniques to ensure its stealthiness and effectiveness.

## Features
Self Injector that uses the following:
- API Hashing: Loads functions using hashed values as to evade static detection
- Sandbox Detection: Implements basic sandbox detection to avoid execution in virtualized or restricted environments (definitely not exhaustive).
- NTDLL Unhooking: Unhooks NTDLL and loads it fresh into memory.
- IAT Obfuscation & Hiding: Loads all functions at runtime to hide functions from IAT.

## Project Structure
- Source Code:
  - main.c: Entry point of the program. Manages the injection process and calls various custom functions.
  - check.c: Contains functions for checking specific conditions or states.
  - converter.c: Handles data conversion tasks.
  - custom-functions.c: Contains custom implementations of various functions to avoid direct API calls.
  - dsh.c: Contains `JenkinsOneAtATime32Bit`.

- Project Files:
  - IDR.vcxproj, IDR.vcxproj.filters, IDR.vcxproj.user: Visual Studio project files for building the injector.
  - IDR.sln: Visual Studio solution file.

## Usage
- Building the Project:
  - Open the IDR.sln solution file in Visual Studio.
  - Place xored payload in hex string format. (e.g. `const char* hexString = "6368616e67656d65";`)
  - Place xor key in byte format. (e.g. `const char key[] = "\x63\x68\x61\x6e\x67\x65\x6d\x65";`) 
  - Build the project to generate the executable.

- Running the Injector:
  - Execute the built executable on the target system.

- Customization:
  - Modify the source code as needed to adjust the injection techniques or add new functionality.

## License

This project is licensed under the terms of the LICENSE file.
