using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("DistControl Server Setup")]
[assembly: AssemblyDescription("DistControl Server Windows installer")]
[assembly: AssemblyCompany("DistControl")]
[assembly: AssemblyProduct("DistControl Server")]
[assembly: AssemblyCopyright("Copyright 2026")]
[assembly: AssemblyVersion("0.8.5.0")]
[assembly: AssemblyFileVersion("0.8.5.0")]
[assembly: ComVisible(false)]

internal static class ServerSetupBootstrapper
{
    private const string ServiceName = "DistControlServer";
    private const string ServiceDisplayName = "DistControl Server";
    private const string ListenUrl = "http://+:8765/";
    private const int ServerPort = 8765;
    private static readonly byte[] Marker = Encoding.ASCII.GetBytes("DCSRV001");

    private const uint ScManagerAllAccess = 0xF003F;
    private const uint ServiceAllAccess = 0xF01FF;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceNoChange = 0xFFFFFFFF;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr serviceManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateService(
        IntPtr serviceManager,
        string serviceName,
        string displayName,
        uint desiredAccess,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPath,
        string loadOrderGroup,
        IntPtr tagId,
        string dependencies,
        string serviceStartName,
        string password);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(
        IntPtr service,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPath,
        string loadOrderGroup,
        IntPtr tagId,
        string dependencies,
        string serviceStartName,
        string password,
        string displayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private sealed class InstallProgressForm : Form
    {
        private readonly string _payloadDirectory;
        private readonly Label _status;
        private readonly TextBox _details;

        public Exception Error { get; private set; }

        public InstallProgressForm(string payloadDirectory)
        {
            _payloadDirectory = payloadDirectory;
            Text = "Установка DistControl Server";
            Width = 620;
            Height = 310;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            MinimizeBox = false;
            ControlBox = false;

            Label title = new Label();
            title.Left = 18;
            title.Top = 18;
            title.Width = 565;
            title.Height = 25;
            title.Text = "Установка серверной части DistControl";
            title.Font = new Font(title.Font, FontStyle.Bold);
            Controls.Add(title);

            Label description = new Label();
            description.Left = 18;
            description.Top = 49;
            description.Width = 565;
            description.Height = 38;
            description.Text = "Установщик обновит файлы, настроит службу и разрешит входящие подключения на порту 8765.";
            Controls.Add(description);

            ProgressBar progress = new ProgressBar();
            progress.Left = 18;
            progress.Top = 94;
            progress.Width = 565;
            progress.Height = 22;
            progress.Style = ProgressBarStyle.Marquee;
            progress.MarqueeAnimationSpeed = 25;
            Controls.Add(progress);

            _status = new Label();
            _status.Left = 18;
            _status.Top = 126;
            _status.Width = 565;
            _status.Height = 24;
            _status.Text = "Подготовка...";
            Controls.Add(_status);

            _details = new TextBox();
            _details.Left = 18;
            _details.Top = 156;
            _details.Width = 565;
            _details.Height = 100;
            _details.Multiline = true;
            _details.ReadOnly = true;
            _details.ScrollBars = ScrollBars.Vertical;
            Controls.Add(_details);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            BackgroundWorker worker = new BackgroundWorker();
            worker.DoWork += delegate
            {
                InstallServer(_payloadDirectory, Report);
            };
            worker.RunWorkerCompleted += delegate(object sender, RunWorkerCompletedEventArgs args)
            {
                Error = args.Error;
                DialogResult = Error == null ? DialogResult.OK : DialogResult.Abort;
                Close();
            };
            worker.RunWorkerAsync();
        }

        private void Report(string message)
        {
            if (IsDisposed || string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            try
            {
                BeginInvoke((MethodInvoker)delegate
                {
                    _status.Text = message;
                    _details.AppendText(message + Environment.NewLine);
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
        Application.SetCompatibleTextRenderingDefault(false);

        string tempDirectory = null;
        try
        {
            tempDirectory = Path.Combine(Path.GetTempPath(), "DistControl-Server-Setup-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDirectory);
            string zipPath = Path.Combine(tempDirectory, "payload.zip");
            ExtractAppendedPayload(zipPath);
            ZipFile.ExtractToDirectory(zipPath, tempDirectory);

            using (InstallProgressForm form = new InstallProgressForm(tempDirectory))
            {
                form.ShowDialog();
                if (form.Error != null)
                {
                    throw form.Error;
                }
            }

            MessageBox.Show(
                "DistControl Server установлен и запущен.\r\n\r\n" +
                "Адрес сервера: http://localhost:8765/\r\n" +
                "Доступ к центральной консоли: только участники Domain Admins.",
                "DistControl Server",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Не удалось установить DistControl Server.\r\n\r\n" + HumanError(ex),
                "DistControl Server",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
        finally
        {
            DeleteTemporaryDirectory(tempDirectory);
        }
    }

    private static void InstallServer(string payloadDirectory, Action<string> report)
    {
        string installDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DistControl Server");
        string dataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DistControlServer");
        string installedServer = Path.Combine(installDirectory, "DistControl.Server.exe");
        string sourceDirectory = Path.Combine(payloadDirectory, "bin");
        string sourceServer = Path.Combine(sourceDirectory, "DistControl.Server.exe");

        if (!File.Exists(sourceServer))
        {
            throw new FileNotFoundException("В установочном пакете отсутствует DistControl.Server.exe.", sourceServer);
        }

        report("Останавливаем предыдущую версию службы...");
        StopServiceIfPresent();
        StopRemainingServerProcess(installedServer);

        report("Подготавливаем каталоги и права доступа...");
        Directory.CreateDirectory(installDirectory);
        Directory.CreateDirectory(dataDirectory);
        ProtectDataDirectory(dataDirectory);

        report("Обновляем серверные файлы...");
        CopyWithRetry(sourceServer, installedServer);
        CopyOptional(sourceDirectory, installDirectory, "DistControl.CentralAdmin.exe");
        CopyOptional(sourceDirectory, installDirectory, "DistControl.Admin.exe");

        report("Создаём ярлык центральной админки...");
        CreateCentralAdminShortcut(installDirectory);

        report("Регистрируем системную службу...");
        string binaryCommand = "\"" + installedServer + "\" --service --url \"" + ListenUrl + "\" --data \"" + dataDirectory + "\"";
        CreateOrUpdateService(binaryCommand);

        report("Настраиваем брандмауэр Windows...");
        ConfigureFirewall();

        report("Запускаем DistControl Server...");
        using (ServiceController controller = new ServiceController(ServiceName))
        {
            controller.Refresh();
            if (controller.Status != ServiceControllerStatus.Running)
            {
                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
        }

        report("Установка завершена.");
    }

    private static void StopServiceIfPresent()
    {
        try
        {
            using (ServiceController controller = new ServiceController(ServiceName))
            {
                ServiceControllerStatus status = controller.Status;
                if (status != ServiceControllerStatus.Stopped)
                {
                    controller.Stop();
                    controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            }
        }
        catch (InvalidOperationException ex)
        {
            Win32Exception win32 = ex.InnerException as Win32Exception;
            if (win32 == null || win32.NativeErrorCode != 1060)
            {
                throw;
            }
        }
    }

    private static void StopRemainingServerProcess(string installedServer)
    {
        foreach (Process process in Process.GetProcessesByName("DistControl.Server"))
        {
            using (process)
            {
                try
                {
                    string processPath = process.MainModule.FileName;
                    if (string.Equals(processPath, installedServer, StringComparison.OrdinalIgnoreCase))
                    {
                        process.Kill();
                        process.WaitForExit(10000);
                    }
                }
                catch (InvalidOperationException)
                {
                }
            }
        }
    }

    private static void CopyOptional(string sourceDirectory, string installDirectory, string fileName)
    {
        string source = Path.Combine(sourceDirectory, fileName);
        if (File.Exists(source))
        {
            CopyWithRetry(source, Path.Combine(installDirectory, fileName));
        }
    }

    private static void CopyWithRetry(string source, string destination)
    {
        Exception lastError = null;
        for (int attempt = 1; attempt <= 10; attempt++)
        {
            try
            {
                File.Copy(source, destination, true);
                return;
            }
            catch (IOException ex)
            {
                lastError = ex;
            }
            catch (UnauthorizedAccessException ex)
            {
                lastError = ex;
            }
            Thread.Sleep(500);
        }

        throw new IOException(
            "Не удалось обновить файл '" + destination + "'. Закройте программы DistControl и повторите установку.",
            lastError);
    }

    private static void CreateCentralAdminShortcut(string installDirectory)
    {
        string target = Path.Combine(installDirectory, "DistControl.CentralAdmin.exe");
        if (!File.Exists(target))
        {
            return;
        }

        string programs = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
        string shortcutDirectory = Path.Combine(programs, "DistControl Server");
        Directory.CreateDirectory(shortcutDirectory);
        string shortcutPath = Path.Combine(shortcutDirectory, "DistControl Central Admin.lnk");

        Type shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null)
        {
            throw new InvalidOperationException("Не удалось создать ярлык центральной админки: WScript.Shell недоступен.");
        }

        object shell = null;
        object shortcut = null;
        try
        {
            shell = Activator.CreateInstance(shellType);
            shortcut = shellType.InvokeMember(
                "CreateShortcut",
                BindingFlags.InvokeMethod,
                null,
                shell,
                new object[] { shortcutPath });
            Type shortcutType = shortcut.GetType();
            shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { target });
            shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { installDirectory });
            shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { "Центральное управление DistControl" });
            shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
        }
        finally
        {
            if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
            if (shell != null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
        }
    }

    private static void ProtectDataDirectory(string dataDirectory)
    {
        DirectorySecurity security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        Directory.SetAccessControl(dataDirectory, security);
    }

    private static void CreateOrUpdateService(string binaryCommand)
    {
        IntPtr serviceManager = OpenSCManager(null, null, ScManagerAllAccess);
        if (serviceManager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось открыть диспетчер служб Windows.");
        }

        try
        {
            IntPtr service = OpenService(serviceManager, ServiceName, ServiceAllAccess);
            if (service == IntPtr.Zero)
            {
                int openError = Marshal.GetLastWin32Error();
                if (openError != 1060)
                {
                    throw new Win32Exception(openError, "Не удалось открыть службу DistControl Server.");
                }

                service = CreateService(
                    serviceManager,
                    ServiceName,
                    ServiceDisplayName,
                    ServiceAllAccess,
                    ServiceWin32OwnProcess,
                    ServiceAutoStart,
                    ServiceErrorNormal,
                    binaryCommand,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null);
                if (service == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось создать службу DistControl Server.");
                }
            }
            else
            {
                bool changed = ChangeServiceConfig(
                    service,
                    ServiceNoChange,
                    ServiceAutoStart,
                    ServiceNoChange,
                    binaryCommand,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null,
                    ServiceDisplayName);
                if (!changed)
                {
                    int changeError = Marshal.GetLastWin32Error();
                    CloseServiceHandle(service);
                    throw new Win32Exception(changeError, "Не удалось обновить службу DistControl Server.");
                }
            }

            CloseServiceHandle(service);
        }
        finally
        {
            CloseServiceHandle(serviceManager);
        }
    }

    private static void ConfigureFirewall()
    {
        string netsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
        RunHidden(netsh, "advfirewall firewall delete rule name=\"DistControl Server\"", true);
        RunHidden(
            netsh,
            "advfirewall firewall add rule name=\"DistControl Server\" dir=in action=allow protocol=TCP localport=" + ServerPort,
            false);
    }

    private static void RunHidden(string fileName, string arguments, bool ignoreFailure)
    {
        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = fileName;
        startInfo.Arguments = arguments;
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;

        using (Process process = Process.Start(startInfo))
        {
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0 && !ignoreFailure)
            {
                throw new InvalidOperationException("Не удалось настроить брандмауэр Windows. " + error + output);
            }
        }
    }

    private static void ExtractAppendedPayload(string destination)
    {
        string executable = Assembly.GetExecutingAssembly().Location;
        using (FileStream input = File.OpenRead(executable))
        {
            long footerLength = sizeof(long) + Marker.Length;
            if (input.Length <= footerLength)
            {
                throw new InvalidDataException("Установочный пакет повреждён: отсутствуют данные сервера.");
            }

            input.Position = input.Length - Marker.Length;
            byte[] marker = new byte[Marker.Length];
            ReadExactly(input, marker, 0, marker.Length);
            for (int index = 0; index < Marker.Length; index++)
            {
                if (marker[index] != Marker[index])
                {
                    throw new InvalidDataException("Установочный пакет повреждён: неверная контрольная метка.");
                }
            }

            input.Position = input.Length - footerLength;
            byte[] lengthBytes = new byte[sizeof(long)];
            ReadExactly(input, lengthBytes, 0, lengthBytes.Length);
            long payloadLength = BitConverter.ToInt64(lengthBytes, 0);
            long payloadOffset = input.Length - footerLength - payloadLength;
            if (payloadLength <= 0 || payloadOffset < 0)
            {
                throw new InvalidDataException("Установочный пакет повреждён: неверный размер данных.");
            }

            input.Position = payloadOffset;
            using (FileStream output = File.Create(destination))
            {
                CopyBytes(input, output, payloadLength);
            }
        }
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        while (count > 0)
        {
            int read = stream.Read(buffer, offset, count);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
            count -= read;
        }
    }

    private static void CopyBytes(Stream input, Stream output, long count)
    {
        byte[] buffer = new byte[81920];
        while (count > 0)
        {
            int requested = (int)Math.Min(buffer.Length, count);
            int read = input.Read(buffer, 0, requested);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }
            output.Write(buffer, 0, read);
            count -= read;
        }
    }

    private static string HumanError(Exception error)
    {
        Exception current = error;
        while (current is TargetInvocationException && current.InnerException != null)
        {
            current = current.InnerException;
        }
        return current.Message;
    }

    private static void DeleteTemporaryDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return;
        }

        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(path, true);
                return;
            }
            catch
            {
                Thread.Sleep(300);
            }
        }
    }
}
