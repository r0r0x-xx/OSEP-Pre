# Prior knowledge for OSEP

This is a repository of notes and material that I consider necessary in advance to opt for the course and the OSEP certification (Techniques of Evasion and 
Breaching Defenses)


This compilation of material is very much influenced by nullgore (GIT) and more!


             ########    #####   ########    #####   ##     ##  
             ##     ##  ##   ##  ##     ##  ##   ##   ##   ##   
             ##     ## ##     ## ##     ## ##     ##   ## ##      
             ########  ##     ## ########  ##     ##    ###        
             ##   ##   ##     ## ##   ##   ##     ##   ## ##      
             ##    ##   ##   ##  ##    ##   ##   ##   ##   ##     
             ##     ##   #####   ##     ##   #####   ##     ## 
             
             
             


## Contents


* [Programming languages](#Programming-languages)
* [Operating System](#Operating-System)
* [Client Side Code Execution](#Client-Side-Code-Execution)
* [Process Injection and Migration](#Process-Injection-and-Migration)
* [Introduction to Antivirus Evasion](#Introduction-to-Antivirus-Evasion)
* [Advanced Antivirus Evasion](#Advanced-Antivirus-Evasion)
* [Application Whitelisting](#Application-Whitelisting)
* [Bypassing Network Filters](#Bypassing-Network-Filters)
* [Linux Post-Exploitation](#Linux-Post-Exploitation)
* [Kiosk Breakouts](#Kiosk-Breakouts)
* [Windows Credentials](#Windows-Credentials)
* [Windows Lateral Movement](#Windows-Lateral-Movement)
* [Linux Lateral Movement](#Linux-Lateral-Movement)
* [Microsoft SQL Attacks](#Microsoft-SQL-Attacks)
* [Active Directory Exploitation](#Active-Directory-Exploitation)


## Programming languages

For this certification it is very important to have a knowledge base in the following programming languages:

Bash: https://www.youtube.com/watch?v=smbeKPDVs2I 

Python: https://www.youtube.com/playlist?list=PLBf0hzazHTGM_dncTqO9l-0zUQYP0nNPU

PowerShel: https://resources.infosecinstitute.com/topic/powershell-for-pentesters-part-1-introduction-to-powershell-and-cmdlets/ 

C#: https://www.youtube.com/watch?v=GhQdlIFylQ8

Introduction to VBA: https://docs.microsoft.com/en-us/office/vba/library-reference/concepts/getting-started-with-vba-in-office

## Operating System

Win32 API's

Offensive P/Invoke: https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d

Process Injection: https://rastamouse.me/blog/process-injection-dinvoke/

Wiki for .NET developers: https://www.pinvoke.net/

Windows Registry

Win register: https://docs.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users

## Client Side Code Execution 

Staged VS Stageless handlers (Payloads): https://buffered.io/posts/staged-vs-stageless-handlers/

HTML Smuggling: https://outflank.nl/blog/2018/08/14/html-smuggling-explained/

Embed in HTML: https://github.com/Arno0x/EmbedInHTML

Macro Malware: https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/macro-malware

Automatically Macro: 
https://support.microsoft.com/en-us/office/automatically-run-a-macro-when-opening-a-workbook-1e55959b-e077-4c88-a696-c3017600db44

Working Windows API in VBA: https://www.aeternus.sg/how-to-use-windows-api-in-vba/ 

Powershell Shellcode: https://www.powershellgallery.com/packages/PowerSploit/1.0.0.0/Content/CodeExecution%5CInvoke-Shellcode.ps1

Code Execution in VBA Macro: https://www.bitdam.com/2018/05/22/propertybomb-an-old-new-technique-for-arbitrary-code-execution-in-vba-macro/

MSBuild Generator: https://github.com/infosecn1nja/MaliciousMacroMSBuild

PowerShell & Windows API: https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1/

PowerSploit: https://github.com/PowerShellMafia/PowerSploit

PowerShell in Memory: https://isc.sans.edu/forums/diary/Fileless+Malicious+PowerShell+Sample/23081/

DelegateType Reflection: https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/how-to-hook-up-a-delegate-using-reflection

Get Delegate: https://www.powershellgallery.com/packages/poke/1.0.0.2/Content/delegate.ps1

Proxy-Aware PowerShell Communications: https://powershell.org/forums/topic/set-dsclocalconfigurationmanager-and-proxy-awareness/

PowerShell Proxy with Authentication: https://medium.com/river-yang/powershell-working-behind-a-proxy-with-authentication-eb68a337f222

JScript Execution: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-jscript-query

JScript Basic Dropper: https://github.com/hlldz/SpookFlare

Payload Creation and Obfuscation: https://github.com/tyranid/DotNetToJScript

SharpShooter: https://github.com/mdsecactivebreach/SharpShooter

## Process Injection and Migration

Process Injection: 

https://github.com/3xpl01tc0d3r/ProcessInjection
https://rastamouse.me/blog/process-injection-dinvoke/

DLL Injection: 

http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html
https://medium.com/bug-bounty-hunting/dll-injection-attacks-in-a-nutshell-71bc84ac59bd


Reflective DLL Injection: https://github.com/stephenfewer/ReflectiveDLLInjection

DLL Injection via PowerShell: https://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Process Hollowing: https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75





