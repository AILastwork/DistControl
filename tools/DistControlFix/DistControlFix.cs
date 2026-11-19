using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("DistControl Fix")]
[assembly: AssemblyProduct("DistControl")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

// Front end for tools\Switch-DistControlUser.ps1 (embedded as a resource):
// moves the DistControl client on a computer to a new employee.
internal sealed class DistControlFixForm : Form
{
    private const string ScriptResource = "Switch-DistControlUser.ps1";

    private readonly TextBox computerBox = new TextBox();
    private readonly TextBox userBox = new TextBox();
    private readonly Button checkButton = new Button();
    private readonly Button runButton = new Button();
    private readonly TextBox outputBox = new TextBox();
    private Process running;

    private DistControlFixForm()
    {
        Text = "DistControl Fix — смена сотрудника на компьютере";
        Font = new Font("Segoe UI", 9F);
        ClientSize = new Size(760, 520);
        MinimumSize = new Size(560, 380);
        StartPosition = FormStartPosition.CenterScreen;

        Label hint = new Label
        {
            Text = "Удаляет клиент DistControl прежнего сотрудника и готовит установку для нового. " +
                   "После выполнения новый сотрудник входит на компьютер или запускает gpupdate /force.",
            Location = new Point(12, 10),
            Size = new Size(736, 36),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
        };

        Label computerLabel = new Label { Text = "Компьютер:", Location = new Point(12, 56), AutoSize = true };
        computerBox.Location = new Point(160, 52);
        computerBox.Width = 220;
        computerBox.Text = Environment.MachineName;

        Label userLabel = new Label { Text = "Новый сотрудник (логин):", Location = new Point(12, 88), AutoSize = true };
        userBox.Location = new Point(160, 84);
        userBox.Width = 220;

        checkButton.Text = "Проверить";
        checkButton.Location = new Point(400, 51);
        checkButton.Size = new Size(110, 28);
        checkButton.Click += delegate { Start(false); };

        runButton.Text = "Выполнить";
        runButton.Location = new Point(400, 83);
        runButton.Size = new Size(110, 28);
        runButton.Click += delegate { Start(true); };

        outputBox.Multiline = true;
        outputBox.ReadOnly = true;
        outputBox.ScrollBars = ScrollBars.Both;
        outputBox.WordWrap = false;
        outputBox.Font = new Font("Consolas", 9F);
        outputBox.Location = new Point(12, 124);
        outputBox.Size = new Size(736, 384);
        outputBox.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        outputBox.BackColor = SystemColors.Window;

        Controls.AddRange(new Control[] { hint, computerLabel, computerBox, userLabel, userBox, checkButton, runButton, outputBox });
        AcceptButton = checkButton;
    }

    private void Start(bool execute)
    {
        string computer = computerBox.Text.Trim();
        string user = userBox.Text.Trim();
        if (computer.Length == 0 || user.Length == 0)
        {
            MessageBox.Show(this, "Укажите компьютер и логин нового сотрудника.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (!IsSafeValue(computer) || !IsSafeValue(user))
        {
            MessageBox.Show(this, "Имя компьютера и логин не должны содержать кавычек и пробелов.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (execute)
        {
            DialogResult answer = MessageBox.Show(
                this,
                "На компьютере " + computer + " будет удалён клиент DistControl прежнего сотрудника " +
                "(данные сохраняются), и установка будет подготовлена для " + user + ".\r\n\r\nПродолжить?",
                Text,
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (answer != DialogResult.Yes)
            {
                return;
            }
        }

        string scriptPath = Path.Combine(Path.GetTempPath(), "DistControlFix-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(scriptPath, ReadScript(), new UTF8Encoding(true));

        string command =
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " +
            "& '" + scriptPath + "' -ComputerName '" + computer + "' -NewUser '" + user + "' " +
            (execute ? "-Confirm:$false" : "-WhatIf") + " *>&1 | Out-String -Stream -Width 300; " +
            "exit $LASTEXITCODE";

        ProcessStartInfo info = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"" + command.Replace("\"", "\\\"") + "\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        outputBox.Clear();
        AppendLine((execute ? "Выполнение" : "Проверка (ничего не меняется)") + ": " + computer + ", новый сотрудник " + user);
        SetBusy(true);

        running = new Process { StartInfo = info, EnableRaisingEvents = true };
        running.OutputDataReceived += (s, e) => { if (e.Data != null) AppendLine(e.Data); };
        running.ErrorDataReceived += (s, e) => { if (e.Data != null) AppendLine(e.Data); };
        running.Exited += delegate
        {
            int code = running.ExitCode;
            try { File.Delete(scriptPath); } catch { }
            BeginInvoke(new Action(delegate
            {
                AppendLine(string.Empty);
                AppendLine(code == 0 ? "Завершено успешно." : "Завершено с ошибкой (код " + code + ").");
                SetBusy(false);
            }));
        };
        running.Start();
        running.BeginOutputReadLine();
        running.BeginErrorReadLine();
    }

    private static bool IsSafeValue(string value)
    {
        return value.IndexOfAny(new[] { '\'', '"', ' ', '`', ';', '&', '|' }) < 0;
    }

    private static string ReadScript()
    {
        using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ScriptResource))
        using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
        {
            return reader.ReadToEnd();
        }
    }

    private void AppendLine(string line)
    {
        if (InvokeRequired)
        {
            BeginInvoke(new Action<string>(AppendLine), line);
            return;
        }
        outputBox.AppendText(line + Environment.NewLine);
    }

    private void SetBusy(bool busy)
    {
        checkButton.Enabled = !busy;
        runButton.Enabled = !busy;
        computerBox.Enabled = !busy;
        userBox.Enabled = !busy;
        UseWaitCursor = busy;
    }

    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new DistControlFixForm());
    }
}
