using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace ThreatCheck
{
    class Defender : Scanner
    {
        byte[] FileBytes;
        string FilePath;

        public Defender(byte[] file, string base_folder)
        {
            FileBytes = file;
            FilePath = base_folder;
        }

        public void AnalyzeFile()
        {
            if (!Directory.Exists(FilePath))
            {
#if DEBUG
                CustomConsole.WriteDebug(FilePath + " doesn't exist. Creating it...");
#endif
                Directory.CreateDirectory(FilePath);
               
            }

            FilePath = Path.Combine(FilePath, "file.exe");
            File.WriteAllBytes(FilePath, FileBytes);

            var status = ScanFile(FilePath);

            if (status.Result == ScanResult.NoThreatFound)
            {
                CustomConsole.WriteOutput("No threat found!");
                return;
            }
            else
            {
                Malicious = true;
            }

            CustomConsole.WriteOutput($"Target file size: {FileBytes.Length} bytes");
            CustomConsole.WriteOutput("Analyzing...");

            var splitArray = new byte[FileBytes.Length / 2];
            Buffer.BlockCopy(FileBytes, 0, splitArray, 0, FileBytes.Length / 2);
            var lastgood = 0;

            while (!Complete)
            {
#if DEBUG
                CustomConsole.WriteDebug($"Testing {splitArray.Length} bytes");
#endif
                File.WriteAllBytes(FilePath, splitArray);
                status = ScanFile(FilePath);

                if (status.Result == ScanResult.ThreatFound)
                {
#if DEBUG
                    CustomConsole.WriteDebug("Threat found, splitting");
#endif
                    var tmpArray = HalfSplitter(splitArray, lastgood);
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Array.Copy(tmpArray, splitArray, tmpArray.Length);
                }
                else if (status.Result == ScanResult.NoThreatFound)
                {
#if DEBUG
                    CustomConsole.WriteDebug("No threat found, increasing size");
#endif
                    lastgood = splitArray.Length;
                    var tmpArray = Overshot(FileBytes, splitArray.Length);
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Buffer.BlockCopy(tmpArray, 0, splitArray, 0, tmpArray.Length);
                }
            }
            if(File.Exists(FilePath)) File.Delete(FilePath);// clean
        }

        public DefenderScanResult ScanFile(string file, bool getsig = false)
        {
            var result = new DefenderScanResult();

            if (!File.Exists(file))
            {
                result.Result = ScanResult.FileNotFound;
                return result;
            }

            var process = new Process();
            var mpcmdrun = new ProcessStartInfo(@"C:\Program Files\Windows Defender\MpCmdRun.exe")
            {
                Arguments = $"-Scan -ScanType 3 -File \"{file}\" -DisableRemediation -Trace -Level 0x10",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            process.StartInfo = mpcmdrun;
            process.Start();
            process.WaitForExit(30000); //Wait 30s

            if (!process.HasExited)
            {
                process.Kill();
                result.Result = ScanResult.Timeout;
                return result;
            }

            if (getsig)
            {
                string stdout;
                string sigName;

                while ((stdout = process.StandardOutput.ReadLine()) != null)
                {
                    if (stdout.Contains("Threat  "))
                    {
                        string[] sig = stdout.Split(' ');
                        sigName = sig[19]; // Lazy way to get the signature name from MpCmdRun
                        result.Signature = sigName;
                        break;
                    }
                }
            }

            switch (process.ExitCode)
            {
                case 0:
                    result.Result = ScanResult.NoThreatFound;
                    break;
                case 2:
                    result.Result = ScanResult.ThreatFound;
                    break;
                default:
                    result.Result = ScanResult.Error;
                    break;
            }

            return result;
        }
    }

    public class DefenderScanResult
    {
        public ScanResult Result { get; set; }
        public string Signature { get; set; }
    }

    public enum ScanResult
    {
        [Description("No threat found")]
        NoThreatFound,
        [Description("Threat found")]
        ThreatFound,
        [Description("The file could not be found")]
        FileNotFound,
        [Description("Timeout")]
        Timeout,
        [Description("Error")]
        Error
    }
}
