# Prior knowledge for OSEP

This is a repository of notes and material that I consider necessary in advance to opt for the course and the OSEP certification (Techniques of Evasion and 
Breaching Defenses)


This compilation of material is very much influenced by nullg0re (GIT) and more!


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


## Introduction to Antivirus Evasion

Metasploit Encryptors: https://blog.rapid7.com/2019/11/21/metasploit-shellcode-grows-up-encrypted-and-authenticated-c-shells/

Payload Encryption: https://sevrosecurity.com/2019/05/25/bypass-windows-defender-with-a-simple-shell-loader/


## Advanced Antivirus Evasion

Antiscan.me: https://antiscan.me/

ASB Bbypass:

https://rastamouse.me/blog/asb-bypass-pt2/
https://rastamouse.me/blog/asb-bypass-pt3/
https://rastamouse.me/blog/asb-bypass-pt4/


## Application Whitelisting

Intro: https://searchsecurity.techtarget.com/definition/application-whitelisting

Bypasses: https://github.com/api0cradle/UltimateAppLockerByPassList


## Bypassing Network Filters

Domain Fronting: 

https://attack.mitre.org/techniques/T1090/004/

https://medium.com/@malcomvetter/simplifying-domain-fronting-8d23dcb694a0

DNS Tunneling

https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling

https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/


## Linux Post-Exploitation

Command List: https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List


## Kiosk Breakouts

Kiosk Breakouts / Attacks: https://www.trustedsec.com/blog/kioskpos-breakout-keys-in-windows/

Kiosk Windows: https://www.engetsu-consulting.com/blog/kiosk-breakout-windows

Shared DLL Hijacking: : https://www.boiteaklou.fr/Abusing-Shared-Libraries.html


## Windows Credentials

MITRE: https://attack.mitre.org/tactics/TA0006/

SAM Dump: https://www.hackingarticles.in/credential-dumping-sam/

Hardening the Local Admin Account (LAPS):

https://rastamouse.me/blog/laps-pt1/
https://rastamouse.me/blog/laps-pt2/

LAPSPasswords: https://github.com/kfosaaen/Get-LAPSPasswords


## Windows Lateral Movement

Microsoft Defender Lateral Movement Paths: https://docs.microsoft.com/en-us/defender-for-identity/use-case-lateral-movement-path

Offensive Lateral Movement: https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f

Restricting SMB: https://medium.com/palantir/restricting-smb-based-lateral-movement-in-a-windows-environment-ed033b888721


## Linux Lateral Movement

MITRE: https://attack.mitre.org/matrices/enterprise/linux/

Lateral Movement with shell: https://redcanary.com/blog/lateral-movement-with-secure-shell/

Post exploit: https://mrw0r57.github.io/2020-05-31-linux-post-exploitation-10-4/


## Microsoft SQL Attacks

MS SQL Enumeration: 

https://www.mssqltips.com/sqlservertip/2013/find-sql-server-instances-across-your-network-using-windows-powershell/

https://www.mssqltips.com/sqlservertip/4181/inventory-sql-logins-on-a-sql-server-with-powershell/

NC Path Injection

https://gist.github.com/nullbind/7dfca2a6309a4209b5aeef181b676c6e

https://blog.netspi.com/executing-smb-relay-attacks-via-sql-server-using-metasploit/

https://hackingandsecurity.blogspot.com/2017/07/10-places-to-stick-your-unc-path.html

https://secure360.org/wp-content/uploads/2017/05/SQL-Server-Hacking-on-Scale-UsingPowerShell_S.Sutherland.pdf


## Active Directory Exploitation

BloodHound: https://github.com/BloodHoundAD/BloodHound

Ingestors: https://github.com/BloodHoundAD/SharpHound

https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/AzureHound.ps1

https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1

Abusing Object Security Permissions: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces

Unconstrained Delegation:

https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1

https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/

https://www.qomplx.com/qomplx-knowledge-kerberos-delegation-attacks-explained/

Constrained Delegation:

https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/

https://stealthbits.com/blog/constrained-delegation-abuse-abusing-constrained-delegation-to-achieve-elevated-access/

Resource-Based Constrained Delegation:

https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution


Active Directoy Inter-Forest Exploitation:

http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/

https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/

https://adsecurity.org/?p=1588

https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
