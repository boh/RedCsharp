# RedCsharp

![Build](https://github.com/boh/RedCsharp/workflows/Build/badge.svg)

## Offensive C# tools

* [CasperStager](https://github.com/ustayready/CasperStager)
  * PoC for persisting .NET payloads in Windows Notification Facility (WNF) state names using low-level Windows Kernel API calls.
* [CSExec](https://github.com/malcomvetter/CSExec)
  * An implementation of PSExec in C#
* [CSharpCreateThreadExample](https://github.com/djhohnstein/CSharpCreateThreadExample)
  * C# code to run PIC using CreateThread
* [CSharpScripts](https://github.com/Arno0x/CSharpScripts)
  * Collection of C# scripts
* [CSharpSetThreadContext](https://github.com/djhohnstein/CSharpSetThreadContext)
  * C# Shellcode Runner to execute shellcode via CreateRemoteThread and SetThreadContext to evade Get-InjectedThread
* [DnsCache](https://github.com/malcomvetter/DnsCache)
  * This is a reference example for how to call the Windows API to enumerate cached DNS records in the Windows resolver. Proof of concept or pattern only.
* [FreshCookees](https://github.com/P1CKLES/FreshCookees)
  * C# .NET 3.5 tool that keeps proxy auth cookies fresh by maintaining a hidden IE process that navs to your hosted auto refresh page. Uses WMI event listeners to monitor for InstanceDeletionEvents of the Internet Explorer process, and starts a hidden IE process via COM object if no other IE processes are running.
* [GoldenTicket](https://github.com/ZeroPointSecurity/GoldenTicket)
  * This .NET assembly is specifically designed for creating Golden Tickets. It has been built with a custom version of SharpSploit and an old 2.0 alpha (x64) version of Powerkatz.
* [Grouper2](https://github.com/l0ss/Grouper2)
  * Find vulnerabilities in AD Group Policy
* [Inception](https://github.com/two06/Inception)
  * Provides In-memory compilation and reflective loading of C# apps for AV evasion.
* [KittyLitter ](https://github.com/djhohnstein/KittyLitter)
  * Credential Dumper. It is comprised of two components, KittyLitter.exe and KittyScooper.exe. This will bind across TCP, SMB, and MailSlot channels to communicate credential material to lowest privilege attackers.
* [Lockless](https://github.com/GhostPack/Lockless)
  * Lockless allows for the copying of locked files.
* [Minidump](https://github.com/3xpl01tc0d3r/Minidump)
  * The program is designed to dump full memory of the process by specifing process name or process id.
* [MiscTools](https://github.com/rasta-mouse/MiscTools)
  * Miscellaneous Tools
* [NamedPipes](https://github.com/malcomvetter/NamedPipes)
  * A pattern for client/server communication via Named Pipes via C#
* [nopowershell](https://github.com/bitsadmin/nopowershell)
  * PowerShell rebuilt in C# for Red Teaming purposes
* [PurpleSharp](https://github.com/mvelazc0/PurpleSharp)
  * PurpleSharp is a C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments.
* [Reg_Built](https://github.com/P1CKLES/Reg_Built)
  * C# Userland Registry RunKey persistence
* [RemoteProcessInjection](https://github.com/Mr-Un1k0d3r/RemoteProcessInjection)
  * C# remote process injection utility for Cobalt Strike
* [Rubeus](https://github.com/GhostPack/Rubeus)
  * Rubeus is a C# toolset for raw Kerberos interaction and abuses.
* RunProcessAsTask
* [RunSharp](https://github.com/fullmetalcache/RunSharp)
  * Simple program that allows you to run commands as another user without being prompted for their password. This is useful in cases where you don't always get feedback from a prompt, such as the case with some remote shells.
* [SafetyKatz](https://github.com/GhostPack/SafetyKatz)
  * SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader
* [Seatbelt](https://github.com/GhostPack/Seatbelt)
  * Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
* [self-morphing-csharp-binary](https://github.com/bytecode77/self-morphing-csharp-binary)
  * C# binary that mutates its own code, encrypts and obfuscates itself on runtime
* [Sharp-InvokeWMIExec](https://github.com/TheWover/Sharp-InvokeWMIExec)
  * A native C# conversion of Kevin Robertsons Invoke-WMIExec powershell script
* [Sharp-Suite](https://github.com/rvrsh3ll/Sharp-Suite)
  * fork of FuzzySecurity/Sharp-Suite
* [SharpAdidnsdump](https://github.com/b4rtik/SharpAdidnsdump)
  * c# implementation of Active Directory Integrated DNS dumping (authenticated user)
* [SharpAttack](https://github.com/jaredhaight/SharpAttack)
  * SharpAttack is a console for certain things I use often during security assessments. It leverages .NET and the Windows API to perform its work. It contains commands for domain enumeration, code execution, and other fun things.
* [SharpClipHistory](https://github.com/FSecureLABS/SharpClipHistory)
  * SharpClipHistory is a .NET application written in C# that can be used to read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.
* [SharpCloud](https://github.com/chrismaddalena/SharpCloud)
  * Simple C# for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute.
* [SharpCOM](https://github.com/rvrsh3ll/SharpCOM)
  * CSHARP DCOM Fun
* [SharpCompile](https://github.com/SpiderLabs/SharpCompile)
  * SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike.
* [SharpCradle](https://github.com/anthemtotheego/SharpCradle)
  * SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
* [SharpDomainSpray](https://github.com/HunnicCyber/SharpDomainSpray)
  * Basic password spraying tool for internal tests and red teaming
* [SharpDoor](https://github.com/infosecn1nja/SharpDoor)
  * SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
  * SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
* [SharpDump](https://github.com/GhostPack/SharpDump)
  * SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
* [SharpEdge](https://github.com/rvrsh3ll/SharpEdge)
  * C# Implementation of Get-VaultCredential
* [SharPersist](https://github.com/fireeye/SharPersist)
  * Windows persistence toolkit written in C#.
* [SharpExec](https://github.com/anthemtotheego/SharpExec)
  * SharpExec is an offensive security C# tool designed to aid with lateral movement. WMIExec. SMBExec. PSExec. WMI.
* [SharpFinder](https://github.com/s0lst1c3/SharpFinder)
  * Searches for files matching specific criteria on readable shares within the domain.
* [SharpFruit](https://github.com/rvrsh3ll/SharpFruit)
  * A C# penetration testing tool to discover low-haning web fruit via web requests.
* [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
  * application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
* [SharpHide](https://github.com/outflanknl/SharpHide)
  * Tool to create hidden registry keys.
* [SharpInvoke-SMBExec](https://github.com/checkymander/Sharp-SMBExec)
  * SMBExec C# module 
* [SharpLoadImage](https://github.com/b4rtik/SharpLoadImage)
  * Hide .Net assembly into png images
* [SharpLocker](https://github.com/Pickfordmatt/SharpLocker)
  * SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike. 
* [SharpLogger](https://github.com/djhohnstein/SharpLogger)
  * Keylogger written in C#
* [SharpNeedle](https://github.com/ChadSki/SharpNeedle)
  * Inject C# code into a running process. Note: SharpNeedle currently only supports 32-bit processes.
* [SharpPack](https://github.com/mdsecactivebreach/SharpPack)
  * An Insider Threat Toolkit. SharpPack is a toolkit for insider threat assessments that lets you defeat application whitelisting to execute arbitrary DotNet and PowerShell tools.
* [sharppcap](https://github.com/chmorgan/sharppcap)
  * Official repository - Fully managed, cross platform (Windows, Mac, Linux) .NET library for capturing packets
* [SharpPrinter](https://github.com/rvrsh3ll/SharpPrinter)
  * Discover Printers
* [SharpRoast](https://github.com/GhostPack/SharpRoast)
  * SharpRoast is a C# port of various PowerView's Kerberoasting functionality.
* [SharpSC](https://github.com/djhohnstein/SharpSC)
  * Simple .NET assembly to interact with services.
* [SharpSniper](https://github.com/HunnicCyber/SharpSniper)
  * Find specific users in active directory via their username and logon IP address
* [SharpSocks]( https://github.com/nettitude/SharpSocks)
  * Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
* [SharpSploit](https://github.com/cobbr/SharpSploit)
  * SharpSploit is a .NET post-exploitation library written in C# https://sharpsploit.cobbr.io/api/
* [SharpSpray](https://github.com/jnqpblc/SharpSpray)
  * SharpSpray a simple code set to perform a password spraying attack against all users of a domain using LDAP and is compatible with Cobalt Strike.
* [SharpSSDP](https://github.com/rvrsh3ll/SharpSSDP)
  * SSDP Service Discovery
* [SharpTask](https://github.com/jnqpblc/SharpTask)
  * SharpTask is a simple code set to interact with the Task Scheduler service api and is compatible with Cobalt Strike.
* [SharpView](https://github.com/tevora-threat/SharpView)
  * C# implementation of harmj0y's PowerView
* [SharpWeb](https://github.com/djhohnstein/SharpWeb)
  * .NET 2.0 CLR project to retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge.
* [SharpWMI]( https://github.com/GhostPack/SharpWMI)
  * SharpWMI is a C# implementation of various WMI functionality.
* [SharPyShell](https://github.com/antonioCoco/SharPyShell )
  * SharPyShell - tiny and obfuscated ASP.NET webshell for C# web applications
* [SilkETW](https://github.com/fireeye/SilkETW)
  * SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection. While both projects have obvious defensive (and offensive) applications they should primarily be considered as research tools.
* [SneakyService]( https://github.com/malcomvetter/SneakyService)
  * A simple, minimal C# windows service implementation that can be used to demonstrate privilege escalation from misconfigured windows services.
* [Stracciatella](https://github.com/mgeeky/Stracciatella)
  * OpSec-safe Powershell runspace from within C# (aka SharpPick) with AMSI and Script Block Logging disabled at startup
* [taskkill](https://github.com/malcomvetter/taskkill )
  * This is a reference example for how to call the Windows API to enumerate and kill a process similar to taskkill.exe. This is based on (incomplete) MSDN example code. Proof of concept or pattern only.
* [TCPRelayInjecter2](https://github.com/Arno0x/TCPRelayInjecter2)
  * Tool for injecting a "TCP Relay" managed assembly into an unmanaged process. 
* [TikiTorch](https://github.com/rasta-mouse/TikiTorch)
  * Process Injection. The basic concept of CACTUSTORCH is that it spawns a new process, allocates a region of memory, then uses CreateRemoteThread to run the desired shellcode within that target process. Both the process and shellcode are specified by the user.
* [Watson](https://github.com/rasta-mouse/Watson)
  * Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
