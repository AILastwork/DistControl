using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("DiskControl Setup")]
[assembly: AssemblyDescription("DiskControl Windows installer")]
[assembly: AssemblyCompany("DiskControl")]
[assembly: AssemblyProduct("DiskControl")]
[assembly: AssemblyCopyright("Copyright 2026")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]
[assembly: ComVisible(false)]

internal static class SetupBootstrapper
{
    private const string ProductName = "DiskControl";
    private const string DefaultUsageStateDirectory = @"\\dfs\fs\IT\soft\DistKontrol\time";
    private static readonly byte[] Marker = Encoding.ASCII.GetBytes("DKSETUP1");

    private enum WtsInfoClass
    {
        UserName = 5,
        DomainName = 7
    }

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr server,
        int sessionId,
        WtsInfoClass infoClass,
        out IntPtr buffer,
        out int bytesReturned);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    private sealed class PowerShellResult
    {
        public int ExitCode;
        public string Output;
    }

    private sealed class ServiceCredentials
    {
        public string Account;
        public string Password;
        public string UsageStateDirectory;
    }

    private sealed class InstallProgressForm : Form
    {
        private readonly string _launcher;
        private readonly string _workingDirectory;
        private readonly ServiceCredentials _credentials;
        private readonly Label _statusLabel;
        private readonly TextBox _detailsBox;

        public PowerShellResult Result { get; private set; }
        public Exception Error { get; private set; }

        public InstallProgressForm(string launcher, string workingDirectory, ServiceCredentials credentials)
        {
            _launcher = launcher;
            _workingDirectory = workingDirectory;
            _credentials = credentials;

            Text = ProductName + " Setup";
            Width = 590;
            Height = 285;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            MinimizeBox = false;
            ControlBox = false;
            ShowInTaskbar = true;

            Label titleLabel = new Label();
            titleLabel.Left = 18;
            titleLabel.Top = 18;
            titleLabel.Width = 535;
            titleLabel.Height = 24;
            titleLabel.Text = "Установка DiskControl";
            titleLabel.Font = new System.Drawing.Font(titleLabel.Font, System.Drawing.FontStyle.Bold);
            Controls.Add(titleLabel);

            Label textLabel = new Label();
            textLabel.Left = 18;
            textLabel.Top = 48;
            textLabel.Width = 535;
            textLabel.Height = 36;
            textLabel.Text = "Подождите, выполняется копирование файлов, настройка прав и регистрация службы.";
            Controls.Add(textLabel);

            ProgressBar progressBar = new ProgressBar();
            progressBar.Left = 18;
            progressBar.Top = 92;
            progressBar.Width = 535;
            progressBar.Height = 22;
            progressBar.Style = ProgressBarStyle.Marquee;
            progressBar.MarqueeAnimationSpeed = 28;
            Controls.Add(progressBar);

            _statusLabel = new Label();
            _statusLabel.Left = 18;
            _statusLabel.Top = 124;
            _statusLabel.Width = 535;
            _statusLabel.Height = 24;
            _statusLabel.Text = "Подготовка установщика...";
            Controls.Add(_statusLabel);

            _detailsBox = new TextBox();
            _detailsBox.Left = 18;
            _detailsBox.Top = 154;
            _detailsBox.Width = 535;
            _detailsBox.Height = 78;
            _detailsBox.Multiline = true;
            _detailsBox.ReadOnly = true;
            _detailsBox.ScrollBars = ScrollBars.Vertical;
            Controls.Add(_detailsBox);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            StartInstall();
        }

        private void StartInstall()
        {
            BackgroundWorker worker = new BackgroundWorker();
            worker.DoWork += delegate
            {
                Result = RunPowerShell(_launcher, _workingDirectory, _credentials, ReportInstallerLine);
            };
            worker.RunWorkerCompleted += delegate(object sender, RunWorkerCompletedEventArgs e)
            {
                if (e.Error != null)
                {
                    Error = e.Error;
                }
                DialogResult = Error == null ? DialogResult.OK : DialogResult.Abort;
                Close();
            };
            worker.RunWorkerAsync();
        }

        private void ReportInstallerLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line) || IsDisposed)
            {
                return;
            }

            try
            {
                BeginInvoke((MethodInvoker)delegate
                {
                    _statusLabel.Text = HumanInstallStatus(line);
                    _detailsBox.AppendText(line + Environment.NewLine);
                });
            }
            catch
            {
            }
        }
    }

    [STAThread]
    private static int Main()
    {
        Application.EnableVisualStyles();

        string tempRoot = null;
        try
        {
            tempRoot = Path.Combine(Path.GetTempPath(), "DiskControl-Setup-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempRoot);

            string payloadZip = Path.Combine(tempRoot, "payload.zip");
            ExtractAppendedPayload(payloadZip);
            ZipFile.ExtractToDirectory(payloadZip, tempRoot);

            string launcher = Path.Combine(tempRoot, "installer", "Launch-Install-DiskControl.ps1");
            if (!File.Exists(launcher))
            {
                throw new FileNotFoundException("Installer launcher not found.", launcher);
            }

            ServiceCredentials credentials = PromptServiceCredentials();
            if (credentials == null)
            {
                return 1;
            }

            PowerShellResult result = ShowInstallProgress(launcher, tempRoot, credentials);
            if (result.ExitCode != 0)
            {
                MessageBox.Show(
                    BuildInstallFailureMessage(result.ExitCode, result.Output),
                    ProductName + " Setup",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return result.ExitCode;
            }

            MessageBox.Show(
                "Установка DiskControl завершена.",
                ProductName + " Setup",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Не удалось завершить установку DiskControl.\r\n\r\n" +
                "Попробуйте запустить установщик от имени администратора. Если ошибка повторится, отправьте администратору текст ошибки ниже.\r\n\r\n" +
                "Техническая причина: " + ex.Message,
                ProductName + " Setup",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
        finally
        {
            if (!string.IsNullOrEmpty(tempRoot))
            {
                try
                {
                    Directory.Delete(tempRoot, true);
                }
                catch
                {
                }
            }
        }
    }

    private static ServiceCredentials PromptServiceCredentials()
    {
        ServiceCredentials credentials = null;

        using (Form form = new Form())
        {
            form.Text = ProductName + " - учетная запись службы";
            form.Width = 570;
            form.Height = 350;
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.MaximizeBox = false;
            form.MinimizeBox = false;
            form.ShowInTaskbar = true;

            Label info = new Label();
            info.Left = 14;
            info.Top = 14;
            info.Width = 525;
            info.Height = 58;
            info.Text = "Укажите учетную запись Windows, под которой будет работать служба dkclient. DistKontrolUSB будет показывать этого пользователя у занятых USB-токенов вместо SYSTEM.";
            form.Controls.Add(info);

            Label accountLabel = new Label();
            accountLabel.Left = 14;
            accountLabel.Top = 82;
            accountLabel.Width = 120;
            accountLabel.Height = 20;
            accountLabel.Text = "Учетная запись";
            form.Controls.Add(accountLabel);

            TextBox accountBox = new TextBox();
            accountBox.Left = 140;
            accountBox.Top = 78;
            accountBox.Width = 395;
            accountBox.Text = DefaultServiceAccount();
            form.Controls.Add(accountBox);

            Label passwordLabel = new Label();
            passwordLabel.Left = 14;
            passwordLabel.Top = 122;
            passwordLabel.Width = 120;
            passwordLabel.Height = 20;
            passwordLabel.Text = "Пароль";
            form.Controls.Add(passwordLabel);

            TextBox passwordBox = new TextBox();
            passwordBox.Left = 140;
            passwordBox.Top = 118;
            passwordBox.Width = 395;
            passwordBox.UseSystemPasswordChar = true;
            form.Controls.Add(passwordBox);

            Label usageLabel = new Label();
            usageLabel.Left = 14;
            usageLabel.Top = 158;
            usageLabel.Width = 120;
            usageLabel.Height = 20;
            usageLabel.Text = "Папка таймеров";
            form.Controls.Add(usageLabel);

            TextBox usageBox = new TextBox();
            usageBox.Left = 140;
            usageBox.Top = 154;
            usageBox.Width = 395;
            usageBox.Text = DefaultUsageStateDirectoryValue();
            form.Controls.Add(usageBox);

            Label usageHint = new Label();
            usageHint.Left = 140;
            usageHint.Top = 182;
            usageHint.Width = 395;
            usageHint.Height = 34;
            usageHint.Text = "Общая папка таймеров для всех компьютеров. Путь можно изменить; если оставить пустым, будет использован локальный ProgramData.";
            form.Controls.Add(usageHint);

            Label note = new Label();
            note.Left = 14;
            note.Top = 222;
            note.Width = 525;
            note.Height = 34;
            note.Text = "Логин текущего сеанса подставлен автоматически. Введите пароль учетной записи, не PIN-код. Пароль не записывается в файлы и журналы.";
            form.Controls.Add(note);

            Button okButton = new Button();
            okButton.Left = 345;
            okButton.Top = 268;
            okButton.Width = 90;
            okButton.Height = 28;
            okButton.Text = "Установить";
            form.Controls.Add(okButton);

            Button cancelButton = new Button();
            cancelButton.Left = 445;
            cancelButton.Top = 268;
            cancelButton.Width = 90;
            cancelButton.Height = 28;
            cancelButton.Text = "Отмена";
            form.Controls.Add(cancelButton);

            okButton.Click += delegate
            {
                string account = accountBox.Text.Trim();
                string password = passwordBox.Text;
                if (string.IsNullOrWhiteSpace(account))
                {
                    MessageBox.Show("Укажите учетную запись службы, например OSNOVA\\ivanov.", ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    accountBox.Focus();
                    return;
                }
                if (string.IsNullOrEmpty(password))
                {
                    MessageBox.Show("Введите пароль учетной записи службы.", ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    passwordBox.Focus();
                    return;
                }

                string usageStateDirectory = usageBox.Text.Trim();
                if (!string.IsNullOrWhiteSpace(usageStateDirectory))
                {
                    if (usageStateDirectory.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBox.Show("Укажите папку для таймеров, а не файл usage.json.", ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        usageBox.Focus();
                        return;
                    }
                    if (!Path.IsPathRooted(usageStateDirectory))
                    {
                        MessageBox.Show("Папка таймеров должна быть полным путем, например C:\\ProgramData\\DiskControl или \\\\SERVER\\Share\\DiskControl.", ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        usageBox.Focus();
                        return;
                    }
                }

                credentials = new ServiceCredentials
                {
                    Account = account,
                    Password = password,
                    UsageStateDirectory = usageStateDirectory
                };
                form.DialogResult = DialogResult.OK;
                form.Close();
            };

            cancelButton.Click += delegate
            {
                form.DialogResult = DialogResult.Cancel;
                form.Close();
            };

            form.AcceptButton = okButton;
            form.CancelButton = cancelButton;

            if (form.ShowDialog() != DialogResult.OK)
            {
                return null;
            }
        }

        return credentials;
    }

    private static string DefaultServiceAccount()
    {
        string configuredAccount = Environment.GetEnvironmentVariable("DISKCONTROL_SERVICE_ACCOUNT");
        if (!string.IsNullOrWhiteSpace(configuredAccount))
        {
            return configuredAccount.Trim();
        }

        string sessionAccount = InteractiveSessionAccount();
        if (!string.IsNullOrWhiteSpace(sessionAccount))
        {
            return sessionAccount;
        }

        try
        {
            string identity = WindowsIdentity.GetCurrent().Name;
            if (!string.IsNullOrWhiteSpace(identity))
            {
                return identity;
            }
        }
        catch
        {
        }

        if (!string.IsNullOrWhiteSpace(Environment.UserDomainName) &&
            !string.IsNullOrWhiteSpace(Environment.UserName))
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }

        return Environment.UserName ?? string.Empty;
    }

    private static string DefaultUsageStateDirectoryValue()
    {
        string configuredDirectory = Environment.GetEnvironmentVariable("DISKCONTROL_USAGE_STATE_DIR");
        return string.IsNullOrWhiteSpace(configuredDirectory)
            ? DefaultUsageStateDirectory
            : configuredDirectory.Trim();
    }

    private static string InteractiveSessionAccount()
    {
        try
        {
            int sessionId = Process.GetCurrentProcess().SessionId;
            string userName = QuerySessionString(sessionId, WtsInfoClass.UserName);
            if (string.IsNullOrWhiteSpace(userName))
            {
                return string.Empty;
            }

            string domainName = QuerySessionString(sessionId, WtsInfoClass.DomainName);
            return string.IsNullOrWhiteSpace(domainName)
                ? userName
                : domainName + "\\" + userName;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string QuerySessionString(int sessionId, WtsInfoClass infoClass)
    {
        IntPtr buffer = IntPtr.Zero;
        int bytesReturned = 0;
        try
        {
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytesReturned) ||
                buffer == IntPtr.Zero ||
                bytesReturned <= 2)
            {
                return string.Empty;
            }

            return Marshal.PtrToStringUni(buffer) ?? string.Empty;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                WTSFreeMemory(buffer);
            }
        }
    }

    private static PowerShellResult ShowInstallProgress(string launcher, string workingDirectory, ServiceCredentials credentials)
    {
        using (InstallProgressForm form = new InstallProgressForm(launcher, workingDirectory, credentials))
        {
            form.ShowDialog();
            if (form.Error != null)
            {
                throw new InvalidOperationException("Не удалось запустить внутренний установщик PowerShell: " + form.Error.Message, form.Error);
            }
            return form.Result ?? new PowerShellResult
            {
                ExitCode = 1,
                Output = "Installer did not return a result."
            };
        }
    }

    private static PowerShellResult RunPowerShell(string launcher, string workingDirectory, ServiceCredentials credentials, Action<string> onOutputLine)
    {
        var output = new StringBuilder();
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File " + Quote(launcher),
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        if (credentials != null)
        {
            startInfo.EnvironmentVariables["DISKCONTROL_SERVICE_ACCOUNT"] = credentials.Account ?? string.Empty;
            startInfo.EnvironmentVariables["DISKCONTROL_SERVICE_PASSWORD"] = credentials.Password ?? string.Empty;
            startInfo.EnvironmentVariables["DISKCONTROL_USAGE_STATE_DIR"] = credentials.UsageStateDirectory ?? string.Empty;
        }

        using (var process = Process.Start(startInfo))
        {
            if (process == null)
            {
                throw new InvalidOperationException("Не удалось запустить PowerShell для установки.");
            }

            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs args)
            {
                AppendOutputLine(output, args.Data, onOutputLine);
            };
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs args)
            {
                AppendOutputLine(output, args.Data, onOutputLine);
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

    private static void AppendOutputLine(StringBuilder output, string line, Action<string> onOutputLine)
    {
        if (line == null)
        {
            return;
        }

        lock (output)
        {
            output.AppendLine(line);
        }

        if (onOutputLine != null)
        {
            onOutputLine(line);
        }
    }

    private static string HumanInstallStatus(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return "Выполняется установка...";
        }

        string lower = line.ToLowerInvariant();
        if (lower.Contains("install log"))
        {
            return "Подготовка журнала установки...";
        }
        if (lower.Contains("create directories"))
        {
            return "Создание рабочих папок...";
        }
        if (lower.Contains("stop service") || lower.Contains("remove existing service"))
        {
            return "Остановка старой службы...";
        }
        if (lower.Contains("copy "))
        {
            return "Копирование файлов DiskControl...";
        }
        if (lower.Contains("policy"))
        {
            return "Подготовка файла доступа allow.json...";
        }
        if (lower.Contains("configure acl") || lower.Contains("execute acl") || lower.Contains("log on as a service"))
        {
            return "Настройка прав доступа...";
        }
        if (lower.Contains("create service") || lower.Contains("start service") || lower.Contains("service "))
        {
            return "Регистрация и запуск службы dkclient...";
        }
        if (lower.Contains("shortcut"))
        {
            return "Создание ярлыков...";
        }
        if (lower.Contains("uninstall entry"))
        {
            return "Регистрация удаления в Windows...";
        }
        if (lower.Contains("installation completed"))
        {
            return "Завершение установки...";
        }
        if (lower.Contains("warning"))
        {
            return "Установка продолжается, есть предупреждение...";
        }

        return "Выполняется установка...";
    }

    private static string BuildInstallFailureMessage(int exitCode, string output)
    {
        StringBuilder message = new StringBuilder();
        message.AppendLine("Установка DiskControl не завершилась.");
        message.AppendLine();
        message.AppendLine("Причина: " + GuessInstallFailureCause(output));

        string logPath = ExtractLogPath(output, "Install log:");
        if (!string.IsNullOrWhiteSpace(logPath))
        {
            message.AppendLine();
            message.AppendLine("Подробный журнал установки:");
            message.AppendLine(logPath);
        }

        message.AppendLine();
        message.AppendLine("Код ошибки: " + exitCode);
        message.Append(FormatOutputDetails(output));
        return message.ToString();
    }

    private static string GuessInstallFailureCause(string output)
    {
        string text = output ?? string.Empty;
        if (ContainsText(text, "Run this installer from an elevated Administrator") ||
            ContainsText(text, "Access is denied") ||
            ContainsText(text, "Отказано в доступе") ||
            ContainsText(text, "UnauthorizedAccessException"))
        {
            return "не хватило прав. Запустите установщик от имени администратора и проверьте права на C:\\Program Files\\DiskControl и C:\\ProgramData\\DiskControl.";
        }
        if (ContainsText(text, "password") ||
            ContainsText(text, "Log on as a service") ||
            ContainsText(text, "New-Service") ||
            ContainsText(text, "account name is invalid") ||
            ContainsText(text, "logon failure") ||
            ContainsText(text, "неудача входа"))
        {
            return "Windows не смогла зарегистрировать или запустить службу dkclient под указанной учетной записью. Проверьте логин, пароль и право «Вход в качестве службы».";
        }
        if (ContainsText(text, "dkcl64.exe is still running") ||
            ContainsText(text, "Cannot stop a conflicting dkcl64.exe"))
        {
            return "старый процесс dkcl64.exe не удалось остановить. Закройте DiskControl, остановите службу dkclient или перезагрузите компьютер и повторите установку.";
        }
        if (ContainsText(text, "usage state") ||
            ContainsText(text, "UsageStateDir") ||
            ContainsText(text, "network share") ||
            ContainsText(text, "UNC"))
        {
            return "проблема с общей папкой таймеров usage.json. Проверьте путь, доступность сетевой папки и права на чтение/запись для пользователей.";
        }
        if (ContainsText(text, "Service") ||
            ContainsText(text, "Start-Service") ||
            ContainsText(text, "did not reach Running"))
        {
            return "служба dkclient установилась, но не запустилась. Проверьте пароль учетной записи службы, dkcl.ini и журнал событий Windows.";
        }
        if (ContainsText(text, "Required installer input is missing") ||
            ContainsText(text, "Required file not found"))
        {
            return "в установочном пакете не найден обязательный файл. Используйте свежий DiskControl-Setup.exe из папки dist.";
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

    private static void ExtractAppendedPayload(string destinationZip)
    {
        string selfPath = Process.GetCurrentProcess().MainModule.FileName;
        using (var input = new FileStream(selfPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (input.Length < Marker.Length + sizeof(long))
            {
                throw new InvalidDataException("Setup payload marker is missing.");
            }

            input.Position = input.Length - Marker.Length;
            byte[] markerBuffer = new byte[Marker.Length];
            ReadExactly(input, markerBuffer, 0, markerBuffer.Length);
            for (int i = 0; i < Marker.Length; ++i)
            {
                if (markerBuffer[i] != Marker[i])
                {
                    throw new InvalidDataException("Setup payload marker is invalid.");
                }
            }

            input.Position = input.Length - Marker.Length - sizeof(long);
            byte[] lengthBuffer = new byte[sizeof(long)];
            ReadExactly(input, lengthBuffer, 0, lengthBuffer.Length);
            long payloadLength = BitConverter.ToInt64(lengthBuffer, 0);
            long payloadStart = input.Length - Marker.Length - sizeof(long) - payloadLength;
            if (payloadLength <= 0 || payloadStart < 0)
            {
                throw new InvalidDataException("Setup payload length is invalid.");
            }

            input.Position = payloadStart;
            using (var output = new FileStream(destinationZip, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                CopyBytes(input, output, payloadLength);
            }
        }
    }

    private static void CopyBytes(Stream input, Stream output, long bytesToCopy)
    {
        byte[] buffer = new byte[1024 * 1024];
        long remaining = bytesToCopy;
        while (remaining > 0)
        {
            int read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read <= 0)
            {
                throw new EndOfStreamException("Unexpected end of setup payload.");
            }
            output.Write(buffer, 0, read);
            remaining -= read;
        }
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        int total = 0;
        while (total < count)
        {
            int read = stream.Read(buffer, offset + total, count - total);
            if (read <= 0)
            {
                throw new EndOfStreamException("Unexpected end of file.");
            }
            total += read;
        }
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }
}
