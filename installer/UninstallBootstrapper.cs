using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("DiskControl Uninstall")]
[assembly: AssemblyDescription("DiskControl Windows uninstaller")]
[assembly: AssemblyCompany("DiskControl")]
[assembly: AssemblyProduct("DiskControl")]
[assembly: AssemblyCopyright("Copyright 2026")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]
[assembly: ComVisible(false)]

internal static class UninstallBootstrapper
{
    private const string ProductName = "DiskControl";

    private sealed class Options
    {
        public bool FromTemp;
        public bool RemoveData;
        public string InstallDir;
    }

    private sealed class PowerShellResult
    {
        public int ExitCode;
        public string Output;
    }

    [STAThread]
    private static int Main(string[] args)
    {
        Application.EnableVisualStyles();

        try
        {
            Options options = ParseOptions(args);
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string installDir = ResolveInstallDirectory(baseDir, options.InstallDir);

            if (!options.FromTemp && IsPathInside(baseDir, installDir))
            {
                RelaunchFromTemp(installDir, options.RemoveData);
                return 0;
            }

            string launcher = FindLauncher(baseDir, installDir);
            PowerShellResult result = RunPowerShell(launcher, SafeWorkingDirectory(), options.RemoveData);
            if (result.ExitCode != 0)
            {
                MessageBox.Show(
                    BuildUninstallFailureMessage(result.ExitCode, result.Output),
                    ProductName + " Uninstall",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return result.ExitCode;
            }

            MessageBox.Show(
                "DiskControl удалён.",
                ProductName + " Uninstall",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Не удалось завершить удаление DiskControl.\r\n\r\n" +
                "Запустите удаление от имени администратора. Если ошибка повторится, отправьте администратору текст ниже.\r\n\r\n" +
                "Техническая причина: " + ex.Message,
                ProductName + " Uninstall",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
    }

    private static Options ParseOptions(string[] args)
    {
        Options options = new Options();
        for (int i = 0; i < args.Length; ++i)
        {
            string arg = args[i] ?? string.Empty;
            if (EqualsArg(arg, "--from-temp"))
            {
                options.FromTemp = true;
            }
            else if (EqualsArg(arg, "--remove-data") || EqualsArg(arg, "-RemoveData") || EqualsArg(arg, "/RemoveData"))
            {
                options.RemoveData = true;
            }
            else if ((EqualsArg(arg, "--install-dir") || EqualsArg(arg, "-InstallDir")) && i + 1 < args.Length)
            {
                options.InstallDir = args[++i];
            }
            else if (arg.StartsWith("--install-dir=", StringComparison.OrdinalIgnoreCase))
            {
                options.InstallDir = arg.Substring("--install-dir=".Length);
            }
        }

        return options;
    }

    private static bool EqualsArg(string left, string right)
    {
        return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    }

    private static string ResolveInstallDirectory(string baseDir, string overrideDir)
    {
        if (!string.IsNullOrWhiteSpace(overrideDir))
        {
            return FullPathWithSlash(overrideDir);
        }

        string registryDir = ReadInstallLocationFromRegistry();
        if (!string.IsNullOrWhiteSpace(registryDir))
        {
            return FullPathWithSlash(registryDir);
        }

        if (File.Exists(Path.Combine(baseDir, "installer", "Launch-Uninstall-DiskControl.ps1")))
        {
            return FullPathWithSlash(baseDir);
        }

        string programFilesDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DiskControl");
        if (Directory.Exists(programFilesDir))
        {
            return FullPathWithSlash(programFilesDir);
        }

        string programFilesX86Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "DiskControl");
        if (Directory.Exists(programFilesX86Dir))
        {
            return FullPathWithSlash(programFilesX86Dir);
        }

        return FullPathWithSlash(baseDir);
    }

    private static string FullPathWithSlash(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        string full = Path.GetFullPath(path);
        if (!full.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
        {
            full += Path.DirectorySeparatorChar;
        }
        return full;
    }

    private static bool IsPathInside(string candidate, string parent)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(parent))
        {
            return false;
        }

        string fullCandidate = FullPathWithSlash(candidate);
        string fullParent = FullPathWithSlash(parent);
        return fullCandidate.StartsWith(fullParent, StringComparison.OrdinalIgnoreCase);
    }

    private static void RelaunchFromTemp(string installDir, bool removeData)
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "DiskControl-Uninstall-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        string selfPath = Process.GetCurrentProcess().MainModule.FileName;
        string tempExe = Path.Combine(tempDir, "Uninstall-DiskControl.exe");
        File.Copy(selfPath, tempExe, true);

        StringBuilder arguments = new StringBuilder();
        arguments.Append("--from-temp --install-dir ");
        arguments.Append(Quote(installDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)));
        if (removeData)
        {
            arguments.Append(" --remove-data");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = tempExe,
            Arguments = arguments.ToString(),
            WorkingDirectory = tempDir,
            UseShellExecute = false
        };

        Process.Start(startInfo);
    }

    private static string FindLauncher(string baseDir, string installDir)
    {
        string[] candidates = new string[]
        {
            Path.Combine(installDir ?? string.Empty, "installer", "Launch-Uninstall-DiskControl.ps1"),
            Path.Combine(baseDir, "installer", "Launch-Uninstall-DiskControl.ps1"),
            Path.Combine(baseDir, "DiskControl-Installer", "installer", "Launch-Uninstall-DiskControl.ps1"),
            Path.Combine(ReadInstallLocationFromRegistry(), "installer", "Launch-Uninstall-DiskControl.ps1"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DiskControl", "installer", "Launch-Uninstall-DiskControl.ps1"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "DiskControl", "installer", "Launch-Uninstall-DiskControl.ps1")
        };

        foreach (string candidate in candidates)
        {
            if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(
            "Не найден скрипт удаления. Запустите свежий DiskControl-Setup.exe повторно, затем выполните удаление ещё раз, либо используйте отдельный Uninstall-DiskControl.exe из установочного пакета.",
            candidates[0]);
    }

    private static string ReadInstallLocationFromRegistry()
    {
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\DiskControl"))
            {
                if (key == null)
                {
                    return string.Empty;
                }

                object value = key.GetValue("InstallLocation");
                return value == null ? string.Empty : value.ToString();
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string SafeWorkingDirectory()
    {
        try
        {
            string temp = Path.GetTempPath();
            if (Directory.Exists(temp))
            {
                return temp;
            }
        }
        catch
        {
        }

        return Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    }

    private static PowerShellResult RunPowerShell(string launcher, string workingDirectory, bool removeData)
    {
        var output = new StringBuilder();
        string arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File " + Quote(launcher);
        if (removeData)
        {
            arguments += " -RemoveData";
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using (var process = Process.Start(startInfo))
        {
            if (process == null)
            {
                throw new InvalidOperationException("Не удалось запустить PowerShell для удаления.");
            }

            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
            {
                AppendOutputLine(output, eventArgs.Data);
            };
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
            {
                AppendOutputLine(output, eventArgs.Data);
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.WaitForExit();
            process.WaitForExit();

            return new PowerShellResult
            {
                ExitCode = process.ExitCode,
                Output = output.ToString()
            };
        }
    }

    private static void AppendOutputLine(StringBuilder output, string line)
    {
        if (line == null)
        {
            return;
        }

        lock (output)
        {
            output.AppendLine(line);
        }
    }

    private static string BuildUninstallFailureMessage(int exitCode, string output)
    {
        StringBuilder message = new StringBuilder();
        message.AppendLine("Удаление DiskControl не завершилось.");
        message.AppendLine();
        message.AppendLine("Причина: " + GuessUninstallFailureCause(output));

        string logPath = ExtractLogPath(output, "Uninstall log:");
        if (!string.IsNullOrWhiteSpace(logPath))
        {
            message.AppendLine();
            message.AppendLine("Подробный журнал удаления:");
            message.AppendLine(logPath);
        }

        message.AppendLine();
        message.AppendLine("Код ошибки: " + exitCode);
        message.Append(FormatOutputDetails(output));
        return message.ToString();
    }

    private static string GuessUninstallFailureCause(string output)
    {
        string text = output ?? string.Empty;
        if (ContainsText(text, "Run this uninstaller from an elevated Administrator") ||
            ContainsText(text, "Access is denied") ||
            ContainsText(text, "Отказано в доступе") ||
            ContainsText(text, "UnauthorizedAccessException"))
        {
            return "не хватило прав на удаление файлов или службы. Запустите удаление от имени администратора.";
        }
        if (ContainsText(text, "dkcl64.exe is still running") ||
            ContainsText(text, "Stop dkcl64.exe"))
        {
            return "процесс dkcl64.exe ещё работает и держит файлы. Закройте DiskControl, остановите службу dkclient или перезагрузите компьютер и повторите удаление.";
        }
        if (ContainsText(text, "sc.exe") ||
            ContainsText(text, "Delete service") ||
            ContainsText(text, "Stop service"))
        {
            return "Windows не дала остановить или удалить службу dkclient. Проверьте окно «Службы» и повторите удаление после остановки службы.";
        }
        if (ContainsText(text, "Remove-Item") ||
            ContainsText(text, "Cannot grant removal ACL") ||
            ContainsText(text, "take ownership"))
        {
            return "не удалось удалить один из файлов из-за прав доступа. Удалятор попытался восстановить права, но Windows всё ещё запрещает операцию.";
        }
        return "точная причина не определена автоматически. Откройте подробный журнал ниже и пришлите его для разбора.";
    }

    private static bool ContainsText(string text, string fragment)
    {
        return text != null && text.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static string ExtractLogPath(string output, string marker)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return string.Empty;
        }

        string[] lines = output.Replace("\r\n", "\n").Split('\n');
        foreach (string rawLine in lines)
        {
            string line = rawLine.Trim();
            int index = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                return line.Substring(index + marker.Length).Trim();
            }
        }

        return string.Empty;
    }

    private static string FormatOutputDetails(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return string.Empty;
        }

        string text = output.Trim();
        const int maxLength = 2500;
        if (text.Length > maxLength)
        {
            text = "...\r\n" + text.Substring(text.Length - maxLength);
        }

        return "\r\n\r\nТехнические детали:\r\n" + text;
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }
}
