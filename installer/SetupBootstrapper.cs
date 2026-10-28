using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("DistControl Setup")]
[assembly: AssemblyDescription("DistControl Windows installer")]
[assembly: AssemblyCompany("DistControl")]
[assembly: AssemblyProduct("DistControl")]
[assembly: AssemblyCopyright("Copyright 2026")]
[assembly: AssemblyVersion("0.6.4.0")]
[assembly: AssemblyFileVersion("0.6.4.0")]
[assembly: ComVisible(false)]

internal static class SetupBootstrapper
{
    private const string ProductName = "DistControl";
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
        public string TargetUserSid;
        public string TargetProfileDirectory;
        public string InstallDirectory;
        public string DataDirectory;
        public string RoamingAppDataDirectory;
        public string StartMenuDirectory;
        public string DesktopDirectory;
        public bool ConfigureVpn;
        public List<VpnInstallProfile> VpnProfiles = new List<VpnInstallProfile>();
    }

    private sealed class UserInstallContext
    {
        public string Sid;
        public string ProfileDirectory;
        public string InstallDirectory;
        public string DataDirectory;
        public string RoamingAppDataDirectory;
        public string StartMenuDirectory;
        public string DesktopDirectory;
    }

    private sealed class VpnInstallProfile
    {
        public string Id;
        public string Name;
        public string Server;
        public string Psk;
        public string ExpectedPublicIps;
        public string TokenIdentity;

        public VpnInstallProfile Clone()
        {
            return (VpnInstallProfile)MemberwiseClone();
        }
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
            titleLabel.Text = "Установка DistControl";
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
            tempRoot = Path.Combine(Path.GetTempPath(), "DistControl-Setup-" + Guid.NewGuid().ToString("N"));
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
            credentials.Password = string.Empty;
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
                "Установка DistControl завершена.",
                ProductName + " Setup",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Не удалось завершить установку DistControl.\r\n\r\n" +
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
            info.Text = "Укажите текущую учетную запись Windows. DistControl установится только в ее профиль, а служба dkclient будет показывать этого пользователя у занятых USB-токенов.";
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
            usageHint.Text = "Общая папка таймеров для всех компьютеров. Если оставить путь пустым, состояние будет сохранено в локальном профиле пользователя.";
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

            int wrongPasswordAttempts = 0;
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

                // Check the password now instead of failing at service start.
                int logonError = CredentialCheck.Validate(account, password);
                CredentialCheckResult check = CredentialCheck.Classify(logonError);
                if (check != CredentialCheckResult.Valid)
                {
                    string checkMessage = CredentialCheck.Message(check, account, logonError);
                    if (CredentialCheck.CountsAsWrongPassword(check))
                    {
                        wrongPasswordAttempts++;
                        if (wrongPasswordAttempts >= CredentialCheck.MaximumWrongPasswordAttempts)
                        {
                            MessageBox.Show(checkMessage + "\r\n\r\nПароль введен неверно " + wrongPasswordAttempts +
                                " раза. Установка остановлена, чтобы не заблокировать учетную запись политикой домена.",
                                ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            form.DialogResult = DialogResult.Cancel;
                            form.Close();
                            return;
                        }
                        MessageBox.Show(checkMessage + "\r\n\r\nОсталось попыток: " +
                            (CredentialCheck.MaximumWrongPasswordAttempts - wrongPasswordAttempts) + ".",
                            ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        passwordBox.Clear();
                        passwordBox.Focus();
                        return;
                    }
                    if (!CredentialCheck.MayContinueUnverified(check))
                    {
                        MessageBox.Show(checkMessage, ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        accountBox.Focus();
                        return;
                    }
                    if (MessageBox.Show(checkMessage + "\r\n\r\nПродолжить установку без проверки пароля? " +
                            "Если пароль неверный, служба не запустится.",
                            ProductName + " Setup", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    {
                        passwordBox.Focus();
                        return;
                    }
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
                        MessageBox.Show("Папка таймеров должна быть полным путем, например C:\\Users\\user\\AppData\\Local\\DistControl или \\\\SERVER\\Share\\DistControl.", ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        usageBox.Focus();
                        return;
                    }
                }

                UserInstallContext installContext;
                try
                {
                    installContext = ResolveUserInstallContext(account);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Не удалось определить профиль указанного пользователя.\r\n\r\n" + ex.Message,
                        ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    accountBox.Focus();
                    return;
                }

                credentials = new ServiceCredentials
                {
                    Account = account,
                    Password = password,
                    UsageStateDirectory = usageStateDirectory,
                    TargetUserSid = installContext.Sid,
                    TargetProfileDirectory = installContext.ProfileDirectory,
                    InstallDirectory = installContext.InstallDirectory,
                    DataDirectory = installContext.DataDirectory,
                    RoamingAppDataDirectory = installContext.RoamingAppDataDirectory,
                    StartMenuDirectory = installContext.StartMenuDirectory,
                    DesktopDirectory = installContext.DesktopDirectory
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

    private static string ValidateVpnInstallProfile(VpnInstallProfile profile)
    {
        if (profile == null || string.IsNullOrWhiteSpace(profile.Id) ||
            string.IsNullOrWhiteSpace(profile.Name) || string.IsNullOrWhiteSpace(profile.Server) ||
            string.IsNullOrEmpty(profile.Psk) || string.IsNullOrWhiteSpace(profile.ExpectedPublicIps))
        {
            return "Заполните ID, имя подключения, сервер, общий ключ и хотя бы один внешний IP.";
        }
        if (!System.Text.RegularExpressions.Regex.IsMatch(profile.Id.Trim(), "^[A-Za-z0-9._-]+$"))
        {
            return "ID профиля может содержать только латинские буквы, цифры, точку, дефис и подчёркивание.";
        }
        string[] expectedIps = profile.ExpectedPublicIps.Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        if (expectedIps.Length == 0)
        {
            return "Укажите хотя бы один разрешённый внешний IP.";
        }
        foreach (string value in expectedIps)
        {
            IPAddress parsed;
            if (!IPAddress.TryParse(value.Trim(), out parsed))
            {
                return "Некорректный внешний IP: " + value.Trim();
            }
        }
        return string.Empty;
    }

    private static VpnInstallProfile PromptVpnProfile(VpnInstallProfile source)
    {
        VpnInstallProfile result = null;
        VpnInstallProfile initial = source == null ? new VpnInstallProfile() : source.Clone();
        using (Form form = new Form())
        {
            form.Text = ProductName + " - VPN-профиль";
            form.Width = 650;
            form.Height = 400;
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.StartPosition = FormStartPosition.CenterParent;
            form.MaximizeBox = false;
            form.MinimizeBox = false;

            int labelLeft = 16;
            int inputLeft = 180;
            int inputWidth = 430;
            Label idLabel = new Label { Left = labelLeft, Top = 22, Width = 155, Text = "ID профиля" };
            TextBox idBox = new TextBox { Left = inputLeft, Top = 18, Width = inputWidth, Text = initial.Id ?? string.Empty };
            Label nameLabel = new Label { Left = labelLeft, Top = 58, Width = 155, Text = "Имя подключения Windows" };
            TextBox nameBox = new TextBox { Left = inputLeft, Top = 54, Width = inputWidth, Text = initial.Name ?? string.Empty };
            Label serverLabel = new Label { Left = labelLeft, Top = 94, Width = 155, Text = "VPN-сервер" };
            TextBox serverBox = new TextBox { Left = inputLeft, Top = 90, Width = inputWidth, Text = initial.Server ?? string.Empty };
            Label pskLabel = new Label { Left = labelLeft, Top = 130, Width = 155, Text = "Общий ключ L2TP" };
            TextBox pskBox = new TextBox { Left = inputLeft, Top = 126, Width = inputWidth, Text = initial.Psk ?? string.Empty, UseSystemPasswordChar = true };
            Label ipLabel = new Label { Left = labelLeft, Top = 166, Width = 155, Text = "Разрешённые внешние IP" };
            TextBox ipBox = new TextBox { Left = inputLeft, Top = 162, Width = inputWidth, Text = initial.ExpectedPublicIps ?? string.Empty };
            Label tokenLabel = new Label { Left = labelLeft, Top = 202, Width = 155, Text = "Токен" };
            TextBox tokenBox = new TextBox { Left = inputLeft, Top = 198, Width = inputWidth, Text = initial.TokenIdentity ?? string.Empty };
            Label tokenHint = new Label { Left = inputLeft, Top = 226, Width = inputWidth, Height = 34, Text = "Имя или endpoint токена. Поле можно оставить пустым и назначить профиль позже в админке." };
            Label secretHint = new Label { Left = inputLeft, Top = 268, Width = inputWidth, Height = 32, Text = "Общий ключ используется только во время установки и не записывается в allow.json или журналы." };
            Button okButton = new Button { Left = 414, Top = 312, Width = 92, Height = 30, Text = "Сохранить" };
            Button cancelButton = new Button { Left = 516, Top = 312, Width = 92, Height = 30, Text = "Отмена" };

            form.Controls.AddRange(new Control[] { idLabel, idBox, nameLabel, nameBox, serverLabel, serverBox,
                pskLabel, pskBox, ipLabel, ipBox, tokenLabel, tokenBox, tokenHint, secretHint,
                okButton, cancelButton });

            okButton.Click += delegate
            {
                VpnInstallProfile candidate = new VpnInstallProfile
                {
                    Id = idBox.Text.Trim(),
                    Name = nameBox.Text.Trim(),
                    Server = serverBox.Text.Trim(),
                    Psk = pskBox.Text,
                    ExpectedPublicIps = ipBox.Text.Trim(),
                    TokenIdentity = tokenBox.Text.Trim()
                };
                string error = ValidateVpnInstallProfile(candidate);
                if (!string.IsNullOrEmpty(error))
                {
                    MessageBox.Show(error, ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                result = candidate;
                form.DialogResult = DialogResult.OK;
                form.Close();
            };
            cancelButton.Click += delegate { form.DialogResult = DialogResult.Cancel; form.Close(); };
            form.AcceptButton = okButton;
            form.CancelButton = cancelButton;
            form.ShowDialog();
        }
        return result;
    }

    private static List<string> ParseVpnCsvLine(string line)
    {
        List<string> fields = new List<string>();
        StringBuilder field = new StringBuilder();
        bool quoted = false;
        for (int index = 0; index < line.Length; ++index)
        {
            char ch = line[index];
            if (ch == '"')
            {
                if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                {
                    field.Append('"');
                    ++index;
                }
                else
                {
                    quoted = !quoted;
                }
            }
            else if (ch == ';' && !quoted)
            {
                fields.Add(field.ToString());
                field.Clear();
            }
            else
            {
                field.Append(ch);
            }
        }
        fields.Add(field.ToString());
        return fields;
    }

    private static bool PromptVpnConfiguration(ServiceCredentials credentials)
    {
        List<VpnInstallProfile> profiles = new List<VpnInstallProfile>();

        using (Form form = new Form())
        {
            form.Text = ProductName + " - настройка VPN-профилей";
            form.Width = 980;
            form.Height = 590;
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.MaximizeBox = false;
            form.MinimizeBox = false;
            form.ShowInTaskbar = true;

            CheckBox enabledBox = new CheckBox { Left = 16, Top = 16, Width = 600, Height = 24,
                Text = "Создать или обновить VPN-профили Windows", Checked = false };
            Label info = new Label { Left = 16, Top = 44, Width = 930, Height = 34,
                Text = "Можно добавить любое количество профилей вручную или импортировать CSV. Общие ключи не сохраняются в allow.json и журналах." };
            ListView list = new ListView { Left = 16, Top = 82, Width = 930, Height = 330,
                View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
            list.Columns.Add("ID", 100);
            list.Columns.Add("Имя Windows", 150);
            list.Columns.Add("Сервер", 125);
            list.Columns.Add("Внешние IP", 145);
            list.Columns.Add("Токен", 320);
            list.Columns.Add("Ключ", 65);

            Button addButton = new Button { Left = 16, Top = 424, Width = 105, Height = 30, Text = "Добавить" };
            Button editButton = new Button { Left = 131, Top = 424, Width = 105, Height = 30, Text = "Изменить" };
            Button deleteButton = new Button { Left = 246, Top = 424, Width = 105, Height = 30, Text = "Удалить" };
            Button importButton = new Button { Left = 371, Top = 424, Width = 130, Height = 30, Text = "Импорт CSV" };
            Label formatHint = new Label { Left = 16, Top = 464, Width = 930, Height = 32,
                Text = "CSV UTF-8: id;имя Windows;сервер;общий ключ;внешние IP;токен. Первая строка с заголовками необязательна." };
            Button okButton = new Button { Left = 752, Top = 510, Width = 92, Height = 30, Text = "Далее" };
            Button cancelButton = new Button { Left = 854, Top = 510, Width = 92, Height = 30, Text = "Отмена" };
            form.Controls.AddRange(new Control[] { enabledBox, info, list, addButton, editButton, deleteButton,
                importButton, formatHint, okButton, cancelButton });

            Action refreshList = delegate
            {
                list.BeginUpdate();
                list.Items.Clear();
                foreach (VpnInstallProfile profile in profiles)
                {
                    ListViewItem item = new ListViewItem(profile.Id ?? string.Empty);
                    item.SubItems.Add(profile.Name ?? string.Empty);
                    item.SubItems.Add(profile.Server ?? string.Empty);
                    item.SubItems.Add(profile.ExpectedPublicIps ?? string.Empty);
                    item.SubItems.Add(profile.TokenIdentity ?? string.Empty);
                    item.SubItems.Add(string.IsNullOrEmpty(profile.Psk) ? "нет" : "задан");
                    item.Tag = profile;
                    list.Items.Add(item);
                }
                list.EndUpdate();
            };

            Action editSelected = delegate
            {
                if (list.SelectedItems.Count != 1)
                {
                    MessageBox.Show("Выберите один VPN-профиль.", ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                VpnInstallProfile current = (VpnInstallProfile)list.SelectedItems[0].Tag;
                VpnInstallProfile updated = PromptVpnProfile(current);
                if (updated != null)
                {
                    profiles[profiles.IndexOf(current)] = updated;
                    refreshList();
                }
            };

            addButton.Click += delegate
            {
                VpnInstallProfile added = PromptVpnProfile(null);
                if (added != null) { profiles.Add(added); refreshList(); }
            };
            editButton.Click += delegate { editSelected(); };
            list.DoubleClick += delegate { editSelected(); };
            deleteButton.Click += delegate
            {
                if (list.SelectedItems.Count == 0) { return; }
                foreach (ListViewItem selected in list.SelectedItems)
                {
                    profiles.Remove((VpnInstallProfile)selected.Tag);
                }
                refreshList();
            };
            importButton.Click += delegate
            {
                using (OpenFileDialog dialog = new OpenFileDialog())
                {
                    dialog.Filter = "VPN profiles CSV (*.csv)|*.csv|Все файлы (*.*)|*.*";
                    if (dialog.ShowDialog(form) != DialogResult.OK) { return; }
                    try
                    {
                        List<VpnInstallProfile> imported = new List<VpnInstallProfile>();
                        string[] lines = File.ReadAllLines(dialog.FileName, Encoding.UTF8);
                        for (int lineIndex = 0; lineIndex < lines.Length; ++lineIndex)
                        {
                            if (string.IsNullOrWhiteSpace(lines[lineIndex])) { continue; }
                            List<string> fields = ParseVpnCsvLine(lines[lineIndex]);
                            if (fields.Count > 0 && fields[0].Trim().Equals("id", StringComparison.OrdinalIgnoreCase)) { continue; }
                            if (fields.Count != 6) { throw new InvalidDataException("Строка " + (lineIndex + 1) + ": требуется 6 полей."); }
                            VpnInstallProfile profile = new VpnInstallProfile
                            {
                                Id = fields[0].Trim(), Name = fields[1].Trim(), Server = fields[2].Trim(),
                                Psk = fields[3], ExpectedPublicIps = fields[4].Trim(), TokenIdentity = fields[5].Trim()
                            };
                            string error = ValidateVpnInstallProfile(profile);
                            if (!string.IsNullOrEmpty(error)) { throw new InvalidDataException("Строка " + (lineIndex + 1) + ": " + error); }
                            imported.Add(profile);
                        }
                        if (imported.Count == 0) { throw new InvalidDataException("В файле не найдено VPN-профилей."); }
                        DialogResult replace = MessageBox.Show("Заменить текущий список импортированными профилями?\r\n\r\nДа — заменить, Нет — добавить.",
                            ProductName + " Setup", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                        if (replace == DialogResult.Cancel) { return; }
                        if (replace == DialogResult.Yes) { profiles.Clear(); }
                        profiles.AddRange(imported);
                        refreshList();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Не удалось импортировать VPN-профили.\r\n\r\n" + ex.Message,
                            ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            };

            Action updateEnabled = delegate
            {
                bool enabled = enabledBox.Checked;
                list.Enabled = enabled;
                addButton.Enabled = enabled;
                editButton.Enabled = enabled;
                deleteButton.Enabled = enabled;
                importButton.Enabled = enabled;
            };
            enabledBox.CheckedChanged += delegate { updateEnabled(); };

            okButton.Click += delegate
            {
                if (enabledBox.Checked && profiles.Count == 0)
                {
                    MessageBox.Show("Добавьте хотя бы один VPN-профиль или отключите настройку VPN.", ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                HashSet<string> ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (VpnInstallProfile profile in profiles)
                {
                    string error = ValidateVpnInstallProfile(profile);
                    if (!string.IsNullOrEmpty(error))
                    {
                        MessageBox.Show("Профиль " + (profile.Id ?? "") + ": " + error, ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    if (!ids.Add(profile.Id.Trim()))
                    {
                        MessageBox.Show("Повторяется ID VPN-профиля: " + profile.Id, ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    if (!names.Add(profile.Name.Trim()))
                    {
                        MessageBox.Show("Повторяется имя подключения Windows: " + profile.Name, ProductName + " Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }
                credentials.ConfigureVpn = enabledBox.Checked;
                credentials.VpnProfiles = enabledBox.Checked ? new List<VpnInstallProfile>(profiles) : new List<VpnInstallProfile>();
                form.DialogResult = DialogResult.OK;
                form.Close();
            };
            cancelButton.Click += delegate { form.DialogResult = DialogResult.Cancel; form.Close(); };
            form.AcceptButton = okButton;
            form.CancelButton = cancelButton;
            refreshList();
            updateEnabled();
            return form.ShowDialog() == DialogResult.OK;
        }
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

    private static UserInstallContext ResolveUserInstallContext(string account)
    {
        if (string.IsNullOrWhiteSpace(account))
        {
            throw new InvalidOperationException("Учетная запись не указана.");
        }

        SecurityIdentifier sid;
        try
        {
            sid = (SecurityIdentifier)new NTAccount(account.Trim()).Translate(typeof(SecurityIdentifier));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Windows не нашла учетную запись " + account.Trim() + ".", ex);
        }

        string profileDirectory = string.Empty;
        using (RegistryKey profileKey = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid.Value))
        {
            if (profileKey != null)
            {
                object rawPath = profileKey.GetValue("ProfileImagePath", string.Empty, RegistryValueOptions.DoNotExpandEnvironmentNames);
                profileDirectory = Environment.ExpandEnvironmentVariables(rawPath == null ? string.Empty : rawPath.ToString());
            }
        }

        if (string.IsNullOrWhiteSpace(profileDirectory) || !Directory.Exists(profileDirectory))
        {
            throw new DirectoryNotFoundException("Профиль " + account.Trim() + " ещё не создан на этом компьютере. Пользователь должен хотя бы один раз войти в Windows.");
        }

        profileDirectory = Path.GetFullPath(profileDirectory.Trim());
        string localAppData = Path.Combine(profileDirectory, "AppData", "Local");
        string roamingAppData = Path.Combine(profileDirectory, "AppData", "Roaming");
        return new UserInstallContext
        {
            Sid = sid.Value,
            ProfileDirectory = profileDirectory,
            InstallDirectory = Path.Combine(localAppData, "Programs", "DistControl"),
            DataDirectory = Path.Combine(localAppData, "DistControl"),
            RoamingAppDataDirectory = roamingAppData,
            StartMenuDirectory = Path.Combine(roamingAppData, "Microsoft", "Windows", "Start Menu", "Programs", "DistControl"),
            DesktopDirectory = Path.Combine(profileDirectory, "Desktop")
        };
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

    private static string EncodeVpnInstallField(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? string.Empty));
    }

    private static string EncodeVpnInstallSecret(string value)
    {
        byte[] plain = Encoding.UTF8.GetBytes(value ?? string.Empty);
        try
        {
            byte[] encrypted = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(encrypted);
        }
        finally
        {
            Array.Clear(plain, 0, plain.Length);
        }
    }

    private static string WriteVpnProfilesFile(string workingDirectory, ServiceCredentials credentials)
    {
        if (credentials == null || !credentials.ConfigureVpn || credentials.VpnProfiles == null || credentials.VpnProfiles.Count == 0)
        {
            return string.Empty;
        }
        string path = Path.Combine(workingDirectory, "vpn-profiles-" + Guid.NewGuid().ToString("N") + ".install");
        List<string> lines = new List<string>();
        foreach (VpnInstallProfile profile in credentials.VpnProfiles)
        {
            lines.Add(string.Join("\t", new[]
            {
                EncodeVpnInstallField(profile.Id),
                EncodeVpnInstallField(profile.Name),
                EncodeVpnInstallField(profile.Server),
                EncodeVpnInstallSecret(profile.Psk),
                EncodeVpnInstallField(profile.ExpectedPublicIps),
                EncodeVpnInstallField(profile.TokenIdentity)
            }));
        }
        File.WriteAllLines(path, lines.ToArray(), new UTF8Encoding(false));
        return path;
    }

    private static void DeleteVpnProfilesFile(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            return;
        }
        try
        {
            long length = new FileInfo(path).Length;
            if (length > 0 && length <= 1024 * 1024)
            {
                File.WriteAllBytes(path, new byte[(int)length]);
            }
            File.Delete(path);
        }
        catch
        {
        }
    }

    private static PowerShellResult RunPowerShell(string launcher, string workingDirectory, ServiceCredentials credentials, Action<string> onOutputLine)
    {
        var output = new StringBuilder();
        // VPN profiles are intentionally managed by Windows and DistControl Admin.
        // The installer never forwards legacy VPN-creation input to PowerShell.
        string vpnProfilesFile = string.Empty;
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
            startInfo.EnvironmentVariables["DISTCONTROL_TARGET_USER_SID"] = credentials.TargetUserSid ?? string.Empty;
            startInfo.EnvironmentVariables["DISTCONTROL_TARGET_PROFILE_DIR"] = credentials.TargetProfileDirectory ?? string.Empty;
            startInfo.EnvironmentVariables["DISTCONTROL_INSTALL_DIR"] = credentials.InstallDirectory ?? string.Empty;
            startInfo.EnvironmentVariables["DISTCONTROL_DATA_DIR"] = credentials.DataDirectory ?? string.Empty;
            startInfo.EnvironmentVariables["DISTCONTROL_ROAMING_APPDATA_DIR"] = credentials.RoamingAppDataDirectory ?? string.Empty;
            startInfo.EnvironmentVariables["DISTCONTROL_START_MENU_DIR"] = credentials.StartMenuDirectory ?? string.Empty;
            startInfo.EnvironmentVariables["DISTCONTROL_DESKTOP_DIR"] = credentials.DesktopDirectory ?? string.Empty;
        }

        try
        {
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
        finally
        {
            DeleteVpnProfilesFile(vpnProfilesFile);
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
            return "Копирование файлов DistControl...";
        }
        if (lower.Contains("policy"))
        {
            return "Подготовка файла доступа allow.json...";
        }
        if (lower.Contains("configure acl") || lower.Contains("execute acl") || lower.Contains("log on as a service"))
        {
            return "Настройка прав доступа...";
        }
        if (lower.Contains("prepare distkontrolusb settings"))
        {
            return "Подготовка штатного клиента для выбранного пользователя...";
        }
        if (lower.Contains("check that dkclient is ready") || lower.Contains("dkclient is not ready yet"))
        {
            return "Ожидание списка USB-токенов от службы...";
        }
        if (lower.Contains("dkclient is ready"))
        {
            return "Служба отвечает, список USB-токенов получен...";
        }
        if (lower.Contains("configure windows vpn profile"))
        {
            int marker = lower.IndexOf("profile ", StringComparison.Ordinal);
            int quote = line.IndexOf('\'', marker >= 0 ? marker : 0);
            string position = marker >= 0 && quote > marker
                ? line.Substring(marker + "profile ".Length, quote - marker - "profile ".Length).Trim()
                : string.Empty;
            return string.IsNullOrEmpty(position)
                ? "Настройка VPN-профилей Windows..."
                : "Настройка VPN-профиля " + position + "...";
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
        message.AppendLine("Установка DistControl не завершилась.");
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
            return "не хватило прав. Подтвердите UAC администратором и проверьте права на пользовательские папки %LOCALAPPDATA%\\Programs\\DistControl и %LOCALAPPDATA%\\DistControl.";
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
            return "старый процесс dkcl64.exe не удалось остановить. Закройте DistControl, остановите службу dkclient или перезагрузите компьютер и повторите установку.";
        }
        if (ContainsText(text, "Close DistControl before installation"))
        {
            return "во время обновления открыта программа DistControl или админская утилита. Закройте указанные в журнале окна и повторите установку.";
        }
        if (ContainsText(text, "dkclient pipe did not become ready"))
        {
            return "служба dkclient запустилась, но не смогла вернуть список USB-токенов. Проверьте учетную запись службы, файл dkcl.ini и доступность серверов из ManualHubs.";
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
            return "в установочном пакете не найден обязательный файл. Используйте свежий DistControl-Setup.exe из папки dist.";
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
