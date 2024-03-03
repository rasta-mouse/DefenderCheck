## ThreatCheck
Modified version of [Matterpreter's](https://twitter.com/matterpreter) [DefenderCheck](https://github.com/matterpreter/DefenderCheck).

Takes a binary as input (either from a file on disk or a URL), splits it until it pinpoints that exact bytes that the target engine will flag on and prints them to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.

```text
C:\>ThreatCheck.exe --help
  -e, --engine    (Default: Defender) Scanning engine. Options: Defender, AMSI
  -f, --file      Analyze a file on disk
  -u, --url       Analyze a file from a URL
  -b, --base-folder    (Default: C:\Temp) The path to the folder where the file will be copied and analyzed. Should be a Defender exclusion folder
  --help          Display this help screen.
  --version       Display version information.
```

### Example
```text
C:\Users\Rasta>ThreatCheck.exe -f Downloads\Grunt.bin -e AMSI
[+] Target file size: 31744 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0x6D7A
00000000   65 00 22 00 3A 00 22 00  7B 00 32 00 7D 00 22 00   e·"·:·"·{·2·}·"·
00000010   2C 00 22 00 74 00 6F 00  6B 00 65 00 6E 00 22 00   ,·"·t·o·k·e·n·"·
00000020   3A 00 7B 00 33 00 7D 00  7D 00 7D 00 00 43 7B 00   :·{·3·}·}·}··C{·
00000030   7B 00 22 00 73 00 74 00  61 00 74 00 75 00 73 00   {·"·s·t·a·t·u·s·
00000040   22 00 3A 00 22 00 7B 00  30 00 7D 00 22 00 2C 00   "·:·"·{·0·}·"·,·
00000050   22 00 6F 00 75 00 74 00  70 00 75 00 74 00 22 00   "·o·u·t·p·u·t·"·
00000060   3A 00 22 00 7B 00 31 00  7D 00 22 00 7D 00 7D 00   :·"·{·1·}·"·}·}·
00000070   00 80 B3 7B 00 7B 00 22  00 47 00 55 00 49 00 44   ·?³{·{·"·G·U·I·D
00000080   00 22 00 3A 00 22 00 7B  00 30 00 7D 00 22 00 2C   ·"·:·"·{·0·}·"·,
00000090   00 22 00 54 00 79 00 70  00 65 00 22 00 3A 00 7B   ·"·T·y·p·e·"·:·{
000000A0   00 31 00 7D 00 2C 00 22  00 4D 00 65 00 74 00 61   ·1·}·,·"·M·e·t·a
000000B0   00 22 00 3A 00 22 00 7B  00 32 00 7D 00 22 00 2C   ·"·:·"·{·2·}·"·,
000000C0   00 22 00 49 00 56 00 22  00 3A 00 22 00 7B 00 33   ·"·I·V·"·:·"·{·3
000000D0   00 7D 00 22 00 2C 00 22  00 45 00 6E 00 63 00 72   ·}·"·,·"·E·n·c·r
000000E0   00 79 00 70 00 74 00 65  00 64 00 4D 00 65 00 73   ·y·p·t·e·d·M·e·s
000000F0   00 73 00 61 00 67 00 65  00 22 00 3A 00 22 00 7B   ·s·a·g·e·"·:·"·{
```
### Bypaas file locked by Defender error
```text
ThreatCheck.exe -f .\shell.exe
[*] C:\Temp doesn't exist. Creating it...
[+] Target file size: 73802 bytes
[+] Analyzing...
[*] Testing 36901 bytes
[*] No threat found, increasing size
[*] Testing 55351 bytes
[*] Threat found, splitting
[*] Testing 46126 bytes
[*] No threat found, increasing size
[*] Testing 59964 bytes
[*] Threat found, splitting
[*] Testing 53045 bytes

Unhandled Exception: System.IO.IOException: The process cannot access the file 'C:\Temp\file.exe' because it is being used by another process.
   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
   at System.IO.FileStream.Init(String path, FileMode mode, FileAccess access, Int32 rights, Boolean useRights, FileShare share, Int32 bufferSize, FileOptions options, SECURITY_ATTRIBUTES secAttrs, String msgPath, Boolean bFromProxy, Boolean useLongPath, Boolean checkHost)
   at System.IO.FileStream..ctor(String path, FileMode mode, FileAccess access, FileShare share, Int32 bufferSize, FileOptions options, String msgPath, Boolean bFromProxy, Boolean useLongPath, Boolean checkHost)
   at System.IO.File.InternalWriteAllBytes(String path, Byte[] bytes, Boolean checkHost)
   at ThreatCheck.Defender.AnalyzeFile() in C:\Users\*****\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Defender\Defender.cs:line 55
   at ThreatCheck.Program.ScanWithDefender(Byte[] file) in C:\Users\*****\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Program.cs:line 114
   at ThreatCheck.Program.RunOptions(Options opts) in C:\Users\*****\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Program.cs:line 85
   at CommandLine.ParserResultExtensions.WithParsed[T](ParserResult`1 result, Action`1 action)
   at ThreatCheck.Program.Main(String[] args) in C:\Users\*****\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Program.cs:line 35
```
In this case set an exclusion folder in Windows Defender and pass the path as parameter, e.g.
```text
ThreatCheck.exe -f .\shell.exe -b "C:\excluded_defender_folder"
