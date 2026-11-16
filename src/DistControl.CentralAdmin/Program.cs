using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("DistControl Central Admin")]
[assembly: AssemblyProduct("DistControl")]
[assembly: AssemblyVersion("0.8.4.0")]
[assembly: AssemblyFileVersion("0.8.4.0")]

namespace DistControl.CentralAdmin
{
    public sealed class AdminSettings
    {
        public string ServerUrl = "http://127.0.0.1:8765";
        public Dictionary<string, List<GridColumnLayout>> GridLayouts = new Dictionary<string, List<GridColumnLayout>>();
    }

    public sealed class GridColumnLayout
    {
        public string Name = "";
        public int DisplayIndex;
        public int Width;
    }

    public sealed class ClientSummary
    {
        public string Id = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string LastSeenUtc = "";
        public string LastIpAddress = "";
        public string PolicyRevision = "";
        public string AppliedPolicyRevision = "";
        public string DesiredVersion = "";
        public string UpdateStatus = "";
        public string LastError = "";
        public string AppliedHubRevision = "";
        public string HubStatus = "";
        public bool Online = false;
    }

    public sealed class HubConfiguration
    {
        public string Revision = "";
        public string ManualHubs = "";
        public string DiscoveredManualHubs = "";
        public string UpdatedUtc = "";
        public string UpdatedBy = "";
    }

    public sealed class HubConfigurationUpdateRequest
    {
        public string ManualHubs = "";
    }

    public sealed class PendingEnrollmentSummary
    {
        public string Id = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string RequestedUtc = "";
        public string LastRequestUtc = "";
        public string LastIpAddress = "";
        public string Status = "";
        public string DecidedBy = "";
        public string DecidedUtc = "";
    }

    public sealed class PolicyResponse
    {
        public string Revision = "";
        public string PolicyJson = "";
    }

    public sealed class PolicyUpdateRequest
    {
        public string ExpectedRevision = "";
        public string PolicyJson = "";
        public bool ConfirmMassExpansion = false;
    }

    internal sealed class PolicyChangeSummary
    {
        public int BeforeCount;
        public int AfterCount;
        public int AddedCount;
        public int RemovedCount;

        public bool IsMassExpansion
        {
            get { return AddedCount >= 10 && AfterCount > Math.Max(BeforeCount * 2, BeforeCount + 10); }
        }
    }

    public sealed class UpdateAssignmentRequest
    {
        public string Version = "";
    }

    public sealed class UpdatePackageManifest
    {
        public string Version = "";
    }

    public sealed class CentralLogRecord
    {
        public string Id = "";
        public string ClientId = "";
        public string ReceivedUtc = "";
        public string FileName = "";
        public string Text = "";
    }

    internal sealed class TokenAuditEvent
    {
        public DateTime Timestamp;
        public string User = "";
        public string Action = "";
        public string Endpoint = "";
        public string Token = "";
        public string Product = "";
        public string Result = "";
        public string Details = "";
    }

    internal sealed class TokenSession
    {
        public string User = "";
        public string Employee = "";
        public string Computer = "";
        public string Endpoint = "";
        public string Token = "";
        public string Product = "";
        public DateTime? Connected;
        public DateTime? Disconnected;
        public string Network = "";
        public string Status = "";
    }

    public sealed class AuditRecord
    {
        public string TimestampUtc = "";
        public string Actor = "";
        public string Action = "";
        public string Target = "";
        public string Details = "";
    }

    internal sealed class CentralApi
    {
        private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
        public string ServerUrl;

        public T Json<T>(string method, string path, object body)
        {
            byte[] content = body == null ? new byte[0] : Encoding.UTF8.GetBytes(json.Serialize(body));
            HttpWebRequest request = Create(method, path);
            if (content.Length > 0)
            {
                request.ContentType = "application/json; charset=utf-8";
                request.ContentLength = content.Length;
                using (Stream output = request.GetRequestStream()) output.Write(content, 0, content.Length);
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                return json.Deserialize<T>(reader.ReadToEnd());
        }

        public void UploadUpdate(string version, string path, Action<int> progress)
        {
            FileInfo package = new FileInfo(path);
            HttpWebRequest request = Create("POST", "/api/v1/admin/updates/" + Uri.EscapeDataString(version));
            request.ContentType = "application/zip";
            request.ContentLength = package.Length;
            request.Headers["X-DistControl-SHA256"] = Sha256File(path);
            if (progress != null) progress(0);
            using (FileStream input = File.OpenRead(path))
            using (Stream output = request.GetRequestStream())
            {
                byte[] buffer = new byte[128 * 1024];
                long copied = 0;
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    copied += read;
                    if (progress != null)
                        progress(package.Length == 0 ? 100 : (int)Math.Min(100, copied * 100L / package.Length));
                }
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream input = response.GetResponseStream()) { input.CopyTo(Stream.Null); }
        }

        private HttpWebRequest Create(string method, string path)
        {
            Uri root = new Uri(ServerUrl.EndsWith("/") ? ServerUrl : ServerUrl + "/");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(new Uri(root, path.TrimStart('/')));
            request.Method = method;
            request.Timeout = 30000;
            request.ReadWriteTimeout = 120000;
            request.KeepAlive = false;
            request.UseDefaultCredentials = true;
            request.PreAuthenticate = true;
            return request;
        }

        private static string Sha256(byte[] value)
        {
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(value)).Replace("-", "");
        }

        private static string Sha256File(string path)
        {
            using (FileStream input = File.OpenRead(path))
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "");
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly string settingsPath;
        private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
        private readonly TextBox serverText = new TextBox();
        private readonly Button connectButton = new Button();
        private readonly DataGridView clientsGrid = NewGrid();
        private readonly DataGridView enrollmentsGrid = NewGrid();
        private readonly DataGridView updateClientsGrid = NewGrid();
        private readonly DataGridView logsGrid = NewGrid();
        private readonly DataGridView auditGrid = NewGrid();
        private readonly TabControl tabs = new TabControl();
        private TabPage logsPage;
        private readonly StatusStrip statusStrip = new StatusStrip();
        private readonly ToolStripStatusLabel statusLabel = new ToolStripStatusLabel();
        private readonly TextBox updateVersion = new TextBox();
        private readonly TextBox updatePath = new TextBox();
        private readonly TextBox hubsText = new TextBox();
        private readonly Label hubsInfo = new Label();
        private readonly Button publishButton = new Button();
        private readonly Button assignButton = new Button();
        private readonly ToolStripLabel updateSummaryLabel = new ToolStripLabel();
        private readonly Timer updateStatusTimer = new Timer();
        private readonly Panel operationPanel = new Panel();
        private readonly Label operationLabel = new Label();
        private readonly ProgressBar operationProgress = new ProgressBar();
        private readonly string legacySettingsPath;
        private Dictionary<string, List<GridColumnLayout>> gridLayouts = new Dictionary<string, List<GridColumnLayout>>();
        private bool applyingGridLayout;
        private bool refreshingUpdateClients;
        private bool refreshingEnrollments;
        private CentralApi api;
        private List<ClientSummary> clients = new List<ClientSummary>();
        private readonly Dictionary<string, string> employeeNameCache =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public MainForm()
        {
            Text = "DistControl Admin - центральное управление";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(980, 620);
            Size = new Size(1250, 760);
            Font = new Font("Segoe UI", 9F);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            settingsPath = Path.Combine(localAppData, "DistControlCentralAdmin", "settings.json");
            legacySettingsPath = Path.Combine(localAppData, "DistControl", "central-admin.json");
            BuildUi();
            LoadSettings();
            updateStatusTimer.Interval = 3000;
            updateStatusTimer.Tick += async delegate
            {
                await RefreshUpdateClientsInBackgroundAsync();
                await RefreshEnrollmentsInBackgroundAsync();
            };
        }

        private void BuildUi()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.RowCount = 4;
            root.ColumnCount = 1;
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
            Controls.Add(root);

            TableLayoutPanel connection = new TableLayoutPanel();
            connection.Dock = DockStyle.Fill;
            connection.Padding = new Padding(8, 7, 8, 5);
            connection.ColumnCount = 4;
            connection.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            connection.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70));
            connection.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            connection.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
            connection.Controls.Add(new Label { Text = "Сервер:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
            serverText.Dock = DockStyle.Fill;
            connection.Controls.Add(serverText, 1, 0);
            connection.Controls.Add(new Label
            {
                Text = "Windows: " + ActorName(),
                AutoSize = true,
                Anchor = AnchorStyles.Left
            }, 2, 0);
            connectButton.Text = "Подключиться";
            connectButton.Dock = DockStyle.Fill;
            connectButton.Click += async delegate { await ConnectAsync(); };
            connection.Controls.Add(connectButton, 3, 0);
            root.Controls.Add(connection, 0, 0);

            operationPanel.Dock = DockStyle.Fill;
            operationPanel.Padding = new Padding(10, 5, 10, 5);
            operationPanel.BackColor = SystemColors.ControlLight;
            TableLayoutPanel operationLayout = new TableLayoutPanel();
            operationLayout.Dock = DockStyle.Fill;
            operationLayout.ColumnCount = 2;
            operationLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            operationLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));
            operationLabel.Dock = DockStyle.Fill;
            operationLabel.TextAlign = ContentAlignment.MiddleLeft;
            operationLabel.Text = "Готово к работе";
            operationLabel.Font = new Font(operationLabel.Font, FontStyle.Bold);
            operationProgress.Dock = DockStyle.Fill;
            operationProgress.Visible = false;
            operationProgress.Style = ProgressBarStyle.Marquee;
            operationProgress.MarqueeAnimationSpeed = 25;
            operationLayout.Controls.Add(operationLabel, 0, 0);
            operationLayout.Controls.Add(operationProgress, 1, 0);
            operationPanel.Controls.Add(operationLayout);
            root.Controls.Add(operationPanel, 0, 1);

            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(BuildClientsPage());
            tabs.TabPages.Add(BuildEnrollmentsPage());
            tabs.TabPages.Add(BuildHubsPage());
            tabs.TabPages.Add(BuildLogsPage());
            tabs.TabPages.Add(BuildUpdatesPage());
            tabs.TabPages.Add(BuildAuditPage());
            root.Controls.Add(tabs, 0, 2);

            statusStrip.Items.Add(statusLabel);
            statusStrip.Dock = DockStyle.Fill;
            statusLabel.Text = "Сервер не подключён";
            root.Controls.Add(statusStrip, 0, 3);
        }

        private TabPage BuildClientsPage()
        {
            TabPage page = new TabPage("Компьютеры");
            ToolStrip tools = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Top };
            ToolStripButton refresh = new ToolStripButton("Обновить");
            ToolStripButton edit = new ToolStripButton("Изменить доступы и VPN");
            ToolStripButton import = new ToolStripButton("Восстановить allow.json");
            ToolStripButton logs = new ToolStripButton("Показать журнал токенов");
            refresh.Click += async delegate { await RefreshClientsWithFeedbackAsync(); };
            edit.Click += async delegate { await EditPolicyAsync(); };
            import.Click += async delegate { await ImportPolicyAsync(); };
            logs.Click += async delegate { await RefreshLogsAsync(); };
            tools.Items.Add(refresh);
            tools.Items.Add(new ToolStripSeparator());
            tools.Items.Add(edit);
            tools.Items.Add(import);
            tools.Items.Add(logs);
            page.Controls.Add(clientsGrid);
            page.Controls.Add(tools);
            return page;
        }

        private TabPage BuildEnrollmentsPage()
        {
            TabPage page = new TabPage("Заявки");
            ToolStrip tools = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Top };
            ToolStripButton refresh = new ToolStripButton("Обновить");
            ToolStripButton approve = new ToolStripButton("Разрешить выбранные");
            ToolStripButton reject = new ToolStripButton("Отклонить выбранные");
            refresh.Click += async delegate { await RefreshEnrollmentsWithFeedbackAsync(); };
            approve.Click += async delegate { await DecideEnrollmentsAsync(true); };
            reject.Click += async delegate { await DecideEnrollmentsAsync(false); };
            tools.Items.Add(refresh);
            tools.Items.Add(new ToolStripSeparator());
            tools.Items.Add(approve);
            tools.Items.Add(reject);
            enrollmentsGrid.MultiSelect = true;
            page.Controls.Add(enrollmentsGrid);
            page.Controls.Add(tools);
            return page;
        }

        private TabPage BuildLogsPage()
        {
            TabPage page = new TabPage("Журнал токенов");
            logsPage = page;
            ToolStrip tools = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Top };
            ToolStripButton refresh = new ToolStripButton("Обновить журнал выбранного компьютера");
            refresh.Click += async delegate { await RefreshLogsAsync(); };
            tools.Items.Add(refresh);
            page.Controls.Add(logsGrid);
            page.Controls.Add(tools);
            return page;
        }

        private TabPage BuildHubsPage()
        {
            TabPage page = new TabPage("USB-серверы");
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), RowCount = 4, ColumnCount = 1 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(new Label
            {
                AutoSize = true,
                Text = "По одному адресу в строке. Формат: IPv4:порт. Если порт не указан, используется 6565."
            }, 0, 0);
            hubsText.Multiline = true;
            hubsText.ScrollBars = ScrollBars.Vertical;
            hubsText.AcceptsReturn = true;
            hubsText.Dock = DockStyle.Fill;
            root.Controls.Add(hubsText, 0, 1);
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight };
            Button refresh = new Button { Text = "Обновить", AutoSize = true };
            Button save = new Button { Text = "Сохранить и применить", AutoSize = true };
            refresh.Click += async delegate { await LoadHubsAsync(true); };
            save.Click += async delegate { await SaveHubsAsync(); };
            buttons.Controls.Add(refresh);
            buttons.Controls.Add(save);
            root.Controls.Add(buttons, 0, 2);
            hubsInfo.AutoSize = true;
            hubsInfo.ForeColor = Color.DimGray;
            root.Controls.Add(hubsInfo, 0, 3);
            page.Controls.Add(root);
            return page;
        }

        private TabPage BuildUpdatesPage()
        {
            TabPage page = new TabPage("Обновления");
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1 };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 155));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            TableLayoutPanel panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 3, RowCount = 4 };
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
            panel.Controls.Add(new Label { Text = "Версия:", Anchor = AnchorStyles.Left, AutoSize = true }, 0, 0);
            updateVersion.Dock = DockStyle.Fill;
            panel.Controls.Add(updateVersion, 1, 0);
            panel.Controls.Add(new Label { Text = "ZIP-пакет:", Anchor = AnchorStyles.Left, AutoSize = true }, 0, 1);
            updatePath.Dock = DockStyle.Fill;
            panel.Controls.Add(updatePath, 1, 1);
            Button browse = new Button { Text = "Выбрать…", Dock = DockStyle.Fill };
            browse.Click += delegate
            {
                using (OpenFileDialog dialog = new OpenFileDialog { Filter = "Пакет DistControl (*.zip)|*.zip|Все файлы (*.*)|*.*" })
                    if (dialog.ShowDialog(this) == DialogResult.OK)
                    {
                        try
                        {
                            string packageVersion = ReadUpdatePackageVersion(dialog.FileName);
                            updatePath.Text = dialog.FileName;
                            updateVersion.Text = packageVersion;
                            SetOperationResult("Выбран пакет обновления " + packageVersion + ".");
                        }
                        catch (Exception error) { ShowError(error); }
                    }
            };
            panel.Controls.Add(browse, 2, 1);
            publishButton.Text = "Опубликовать пакет";
            publishButton.Dock = DockStyle.Fill;
            publishButton.Click += async delegate { await PublishUpdateAsync(); };
            panel.Controls.Add(publishButton, 1, 2);
            assignButton.Text = "Назначить выбранным компьютерам";
            assignButton.Dock = DockStyle.Fill;
            assignButton.Click += async delegate { await AssignUpdateAsync(); };
            panel.Controls.Add(assignButton, 1, 3);

            ToolStrip tools = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Fill };
            ToolStripButton refresh = new ToolStripButton("Обновить статусы");
            refresh.Click += async delegate { await RefreshUpdateClientsWithFeedbackAsync(); };
            updateSummaryLabel.Alignment = ToolStripItemAlignment.Right;
            updateSummaryLabel.Text = "Компьютеры ещё не загружены";
            tools.Items.Add(refresh);
            tools.Items.Add(new ToolStripSeparator());
            tools.Items.Add(new ToolStripLabel("Выберите одну или несколько строк для назначения обновления"));
            tools.Items.Add(updateSummaryLabel);

            updateClientsGrid.MultiSelect = true;
            root.Controls.Add(panel, 0, 0);
            root.Controls.Add(tools, 0, 1);
            root.Controls.Add(updateClientsGrid, 0, 2);
            page.Controls.Add(root);
            return page;
        }

        private TabPage BuildAuditPage()
        {
            TabPage page = new TabPage("История изменений");
            ToolStrip tools = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Top };
            ToolStripButton refresh = new ToolStripButton("Обновить");
            refresh.Click += async delegate { await RefreshAuditAsync(); };
            tools.Items.Add(refresh);
            page.Controls.Add(auditGrid);
            page.Controls.Add(tools);
            return page;
        }

        private async Task ConnectAsync()
        {
            SetBusy(true, "Подключение к серверу…");
            try
            {
                api = new CentralApi { ServerUrl = serverText.Text.Trim() };
                SaveSettings();
                await RefreshClientsAsync();
                await RefreshEnrollmentsAsync();
                await LoadHubsAsync(false);
                updateStatusTimer.Start();
                SetOperationResult("Подключено к " + api.ServerUrl + ". Компьютеров: " + clients.Count + ".");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task RefreshClientsWithFeedbackAsync()
        {
            SetBusy(true, "Обновляем список компьютеров…");
            try
            {
                await RefreshClientsAsync();
                SetOperationResult("Список обновлён. Компьютеров: " + clients.Count + ", в сети: " +
                    clients.Count(delegate(ClientSummary c) { return c.Online; }) + ".");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task RefreshClientsAsync()
        {
            RequireApi();
            CaptureGridLayout(clientsGrid, "clients");
            List<ClientSummary> loaded = await Task.Run(delegate { return api.Json<List<ClientSummary>>("GET", "/api/v1/admin/clients", null); });
            clients = loaded ?? new List<ClientSummary>();
            clientsGrid.DataSource = clients.Select(delegate(ClientSummary c)
            {
                return new
                {
                    Состояние = c.Online ? "В сети" : "Не в сети",
                    Компьютер = c.MachineName,
                    Пользователь = c.UserName,
                    Программа = c.AppVersion,
                    Агент = c.AgentVersion,
                    Последняя_связь = LocalTime(c.LastSeenUtc),
                    Политика = c.PolicyRevision == c.AppliedPolicyRevision ? "Применена" : "Ожидает применения",
                    Обновление = c.UpdateStatus,
                    USB_серверы = c.HubStatus,
                    Ошибка = c.LastError,
                    Id = c.Id
                };
            }).ToList();
            FormatGrid(clientsGrid, "clients");
            BindUpdateClientsGrid();
        }

        private async Task RefreshEnrollmentsWithFeedbackAsync()
        {
            SetBusy(true, "Обновляем заявки на подключение…");
            try
            {
                await RefreshEnrollmentsAsync();
                SetOperationResult("Заявки обновлены.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task RefreshEnrollmentsInBackgroundAsync()
        {
            if (api == null || refreshingEnrollments) return;
            try { await RefreshEnrollmentsAsync(); }
            catch { }
        }

        private async Task RefreshEnrollmentsAsync()
        {
            if (refreshingEnrollments) return;
            refreshingEnrollments = true;
            try
            {
                CaptureGridLayout(enrollmentsGrid, "enrollments");
                HashSet<string> selected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (enrollmentsGrid.Columns.Contains("Id"))
                    foreach (DataGridViewRow row in enrollmentsGrid.SelectedRows)
                        selected.Add(Convert.ToString(row.Cells["Id"].Value));

                List<PendingEnrollmentSummary> requests = await Task.Run(delegate
                {
                    return api.Json<List<PendingEnrollmentSummary>>("GET", "/api/v1/admin/enrollments", null);
                });
                enrollmentsGrid.DataSource = (requests ?? new List<PendingEnrollmentSummary>()).Select(delegate(PendingEnrollmentSummary item)
                {
                    return new
                    {
                        Состояние = item.Status,
                        Компьютер = item.MachineName,
                        Пользователь = item.UserName,
                        Программа = item.AppVersion,
                        Агент = item.AgentVersion,
                        IP = item.LastIpAddress,
                        Получена = LocalTime(item.RequestedUtc),
                        Последний_запрос = LocalTime(item.LastRequestUtc),
                        Решение_принял = item.DecidedBy,
                        Id = item.Id
                    };
                }).ToList();
                FormatGrid(enrollmentsGrid, "enrollments");
                enrollmentsGrid.ClearSelection();
                foreach (DataGridViewRow row in enrollmentsGrid.Rows)
                {
                    string id = Convert.ToString(row.Cells["Id"].Value);
                    row.Selected = selected.Contains(id);
                    string status = Convert.ToString(row.Cells["Состояние"].Value);
                    if (status.IndexOf("Отклонена", StringComparison.OrdinalIgnoreCase) >= 0)
                        row.DefaultCellStyle.BackColor = Color.MistyRose;
                    else if (status.IndexOf("Разрешена", StringComparison.OrdinalIgnoreCase) >= 0)
                        row.DefaultCellStyle.BackColor = Color.Honeydew;
                    else
                        row.DefaultCellStyle.BackColor = Color.LightYellow;
                }
            }
            finally { refreshingEnrollments = false; }
        }

        private async Task DecideEnrollmentsAsync(bool approve)
        {
            if (!enrollmentsGrid.Columns.Contains("Id") || enrollmentsGrid.SelectedRows.Count == 0)
            {
                MessageBox.Show(this, "Выберите одну или несколько заявок.", "DistControl",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            List<string> ids = enrollmentsGrid.SelectedRows.Cast<DataGridViewRow>()
                .Select(delegate(DataGridViewRow row) { return Convert.ToString(row.Cells["Id"].Value); })
                .Where(delegate(string id) { return !String.IsNullOrWhiteSpace(id); })
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            string action = approve ? "разрешение" : "отклонение";
            SetBusy(true, "Выполняется " + action + " заявок…");
            try
            {
                await Task.Run(delegate
                {
                    foreach (string id in ids)
                        api.Json<object>("POST", "/api/v1/admin/enrollments/" + id +
                            (approve ? "/approve" : "/reject"), null);
                });
                await RefreshEnrollmentsAsync();
                SetOperationResult((approve ? "Разрешено заявок: " : "Отклонено заявок: ") + ids.Count + ".");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task LoadHubsAsync(bool feedback)
        {
            RequireApi();
            if (feedback) SetBusy(true, "Получаем список USB-серверов…");
            try
            {
                HubConfiguration hubs = await Task.Run(delegate
                {
                    return api.Json<HubConfiguration>("GET", "/api/v1/admin/hubs", null);
                });
                bool usingDiscovered = hubs != null && String.IsNullOrWhiteSpace(hubs.ManualHubs) &&
                    !String.IsNullOrWhiteSpace(hubs.DiscoveredManualHubs);
                string displayed = hubs == null ? "" :
                    (usingDiscovered ? hubs.DiscoveredManualHubs : hubs.ManualHubs) ?? "";
                string[] entries = displayed
                    .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                hubsText.Text = String.Join(Environment.NewLine, entries);
                hubsInfo.Text = usingDiscovered
                    ? "Адреса обнаружены в dkcl.ini клиентов. Проверьте список и нажмите «Сохранить и применить»."
                    : hubs == null || String.IsNullOrWhiteSpace(hubs.Revision)
                    ? "Клиенты ещё не передали адреса. Они продолжают использовать свой текущий dkcl.ini."
                    : "Последнее изменение: " + LocalTime(hubs.UpdatedUtc) + " | " + hubs.UpdatedBy;
                if (feedback) SetOperationResult("Список USB-серверов обновлён.");
            }
            catch (Exception error) { ShowError(error); }
            finally { if (feedback) SetBusy(false, null); }
        }

        private async Task SaveHubsAsync()
        {
            RequireApi();
            string value = hubsText.Text.Trim();
            string question = String.IsNullOrWhiteSpace(value)
                ? "Список пуст. После применения клиенты удалят управляемые маршруты и отключатся от всех USB-серверов. Продолжить?"
                : "Новый список будет применён ко всем подключённым клиентам. Служба dkclient на каждом компьютере кратковременно перезапустится. Продолжить?";
            if (MessageBox.Show(this, question, "DistControl", MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning) != DialogResult.Yes) return;

            SetBusy(true, "Сохраняем список USB-серверов…");
            try
            {
                HubConfiguration saved = await Task.Run(delegate
                {
                    return api.Json<HubConfiguration>("PUT", "/api/v1/admin/hubs",
                        new HubConfigurationUpdateRequest { ManualHubs = value });
                });
                hubsInfo.Text = "Сохранено: " + LocalTime(saved.UpdatedUtc) + " | " + saved.UpdatedBy;
                hubsText.Text = String.Join(Environment.NewLine,
                    (saved.ManualHubs ?? "").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
                SetOperationResult("Список USB-серверов сохранён. Агенты применят его при ближайшей связи.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task RefreshUpdateClientsWithFeedbackAsync()
        {
            SetBusy(true, "Обновляем статусы установки на компьютерах…");
            try
            {
                await RefreshUpdateClientsAsync();
                SetOperationResult("Статусы обновлений актуализированы.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task RefreshUpdateClientsInBackgroundAsync()
        {
            if (api == null || refreshingUpdateClients) return;
            try { await RefreshUpdateClientsAsync(); }
            catch (Exception error) { updateSummaryLabel.Text = "Нет связи: " + HumanError(error); }
        }

        private async Task RefreshUpdateClientsAsync()
        {
            if (refreshingUpdateClients) return;
            refreshingUpdateClients = true;
            try
            {
                RequireApi();
                List<ClientSummary> loaded = await Task.Run(delegate
                {
                    return api.Json<List<ClientSummary>>("GET", "/api/v1/admin/clients", null);
                });
                clients = loaded ?? new List<ClientSummary>();
                BindUpdateClientsGrid();
            }
            finally { refreshingUpdateClients = false; }
        }

        private void BindUpdateClientsGrid()
        {
            CaptureGridLayout(updateClientsGrid, "updates");
            HashSet<string> selected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (updateClientsGrid.Columns.Contains("Id"))
                foreach (DataGridViewRow row in updateClientsGrid.SelectedRows)
                    selected.Add(Convert.ToString(row.Cells["Id"].Value));

            updateClientsGrid.DataSource = clients.Select(delegate(ClientSummary c)
            {
                return new
                {
                    Состояние = c.Online ? "В сети" : "Не в сети",
                    Компьютер = c.MachineName,
                    Пользователь = c.UserName,
                    Установлено = c.AppVersion,
                    Назначено = c.DesiredVersion,
                    Этап = UpdateStage(c),
                    Последняя_связь = LocalTime(c.LastSeenUtc),
                    Ошибка = c.LastError,
                    Id = c.Id
                };
            }).ToList();
            FormatGrid(updateClientsGrid, "updates");

            updateClientsGrid.ClearSelection();
            foreach (DataGridViewRow row in updateClientsGrid.Rows)
            {
                string id = Convert.ToString(row.Cells["Id"].Value);
                ClientSummary client = clients.FirstOrDefault(delegate(ClientSummary c) { return c.Id == id; });
                if (client == null) continue;
                row.Selected = selected.Contains(id);
                if (!String.IsNullOrWhiteSpace(client.LastError) ||
                    (!String.IsNullOrWhiteSpace(client.UpdateStatus) &&
                     client.UpdateStatus.IndexOf("не установлено", StringComparison.OrdinalIgnoreCase) >= 0))
                    row.DefaultCellStyle.BackColor = Color.MistyRose;
                else if (!String.IsNullOrWhiteSpace(client.DesiredVersion) && VersionsEquivalent(client.AppVersion, client.DesiredVersion))
                    row.DefaultCellStyle.BackColor = Color.Honeydew;
                else if (!String.IsNullOrWhiteSpace(client.DesiredVersion))
                    row.DefaultCellStyle.BackColor = Color.LightYellow;
                else if (!client.Online)
                    row.DefaultCellStyle.ForeColor = Color.DimGray;
            }

            int pending = clients.Count(delegate(ClientSummary c)
            {
                return !String.IsNullOrWhiteSpace(c.DesiredVersion) && !VersionsEquivalent(c.AppVersion, c.DesiredVersion);
            });
            int installed = clients.Count(delegate(ClientSummary c)
            {
                return !String.IsNullOrWhiteSpace(c.DesiredVersion) && VersionsEquivalent(c.AppVersion, c.DesiredVersion);
            });
            updateSummaryLabel.Text = "Компьютеров: " + clients.Count + " | устанавливается/ожидает: " + pending + " | установлено: " + installed;
        }

        private static string UpdateStage(ClientSummary client)
        {
            if (String.IsNullOrWhiteSpace(client.DesiredVersion)) return "Не назначено";
            if (VersionsEquivalent(client.AppVersion, client.DesiredVersion)) return "Установлено успешно";
            if (!client.Online) return "Ожидает подключения компьютера";
            return String.IsNullOrWhiteSpace(client.UpdateStatus) ? "Ожидает получения задания агентом" : client.UpdateStatus;
        }

        private string ReadUpdatePackageVersion(string path)
        {
            using (ZipArchive archive = ZipFile.OpenRead(path))
            {
                ZipArchiveEntry entry = archive.GetEntry("manifest.json");
                if (entry == null) throw new InvalidDataException("В ZIP-пакете отсутствует manifest.json.");
                using (StreamReader reader = new StreamReader(entry.Open(), Encoding.UTF8, true))
                {
                    UpdatePackageManifest manifest = json.Deserialize<UpdatePackageManifest>(reader.ReadToEnd());
                    if (manifest == null || String.IsNullOrWhiteSpace(manifest.Version))
                        throw new InvalidDataException("В manifest.json не указана версия обновления.");
                    return manifest.Version.Trim();
                }
            }
        }

        private async Task EditPolicyAsync()
        {
            ClientSummary client = SelectedClient();
            if (client == null) return;
            SetBusy(true, "Получение конфигурации " + client.MachineName + "…");
            string editDirectory = null;
            try
            {
                PolicyResponse policy = await Task.Run(delegate
                {
                    return api.Json<PolicyResponse>("GET", "/api/v1/admin/clients/" + client.Id + "/policy", null);
                });
                SetBusy(true, "Открываем локальную админку для " + client.MachineName + "…");
                editDirectory = CreatePolicyEditSessionDirectory(settingsPath, client.Id);
                string policyPath = Path.Combine(editDirectory, "allow.json");
                File.WriteAllText(policyPath, policy.PolicyJson, new UTF8Encoding(false));
                string before = Sha256(Encoding.UTF8.GetBytes(policy.PolicyJson));
                string adminExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "DistControl.Admin.exe");
                if (!File.Exists(adminExe)) throw new FileNotFoundException("Рядом с центральной консолью нет DistControl.Admin.exe.", adminExe);

                ProcessStartInfo start = new ProcessStartInfo(adminExe, "--policy \"" + policyPath + "\"");
                start.UseShellExecute = true;
                Process process = Process.Start(start);
                SetBusy(true, "Ожидаем завершения редактирования доступов и VPN…");
                await Task.Run(delegate { process.WaitForExit(); });
                SetBusy(true, "Проверяем внесённые изменения…");
                string changed = File.ReadAllText(policyPath, Encoding.UTF8);
                if (Sha256(Encoding.UTF8.GetBytes(changed)) == before)
                {
                    SetOperationResult("Редактирование завершено. Настройки не изменялись.");
                    return;
                }

                PolicyChangeSummary summary = SummarizePolicyChange(policy.PolicyJson, changed);
                string confirmation =
                    "Отправить изменённые доступы и VPN на компьютер «" + client.MachineName + "»?\r\n\r\n" +
                    "Разрешений было: " + summary.BeforeCount + "\r\n" +
                    "Разрешений станет: " + summary.AfterCount + "\r\n" +
                    "Добавлено: " + summary.AddedCount + "\r\n" +
                    "Удалено: " + summary.RemovedCount;
                if (MessageBox.Show(this,
                    confirmation,
                    "DistControl", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

                if (summary.IsMassExpansion && MessageBox.Show(this,
                    "Обнаружено массовое расширение доступа: добавляется " + summary.AddedCount +
                    " токенов.\r\n\r\nПродолжайте только если вы действительно выбрали эти токены вручную.",
                    "Подтверждение массового изменения", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                PolicyUpdateRequest request = new PolicyUpdateRequest
                {
                    ExpectedRevision = policy.Revision,
                    PolicyJson = changed,
                    ConfirmMassExpansion = summary.IsMassExpansion
                };
                SetBusy(true, "Отправляем изменённые доступы и VPN на сервер…");
                await Task.Run(delegate
                {
                    api.Json<PolicyResponse>("PUT", "/api/v1/admin/clients/" + client.Id + "/policy", request);
                });
                await RefreshClientsAsync();
                SetOperationResult("Изменения сохранены на сервере и ожидают применения клиентом.");
            }
            catch (Exception error) { ShowError(error); }
            finally
            {
                TryDeletePolicyEditSession(editDirectory);
                SetBusy(false, null);
            }
        }

        private static string CreatePolicyEditSessionDirectory(string settingsFile, string clientId)
        {
            string root = Path.Combine(Path.GetDirectoryName(settingsFile), "edit-sessions", clientId ?? "unknown");
            string directory = Path.Combine(root,
                DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" +
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            return directory;
        }

        private static void TryDeletePolicyEditSession(string directory)
        {
            if (String.IsNullOrWhiteSpace(directory)) return;
            try
            {
                if (Directory.Exists(directory)) Directory.Delete(directory, true);
            }
            catch
            {
                // A failed cleanup is harmless; the next run uses a different isolated directory.
            }
        }

        private static PolicyChangeSummary SummarizePolicyChange(string beforeJson, string afterJson)
        {
            HashSet<string> before = PolicyAccessKeys(beforeJson);
            HashSet<string> after = PolicyAccessKeys(afterJson);
            return new PolicyChangeSummary
            {
                BeforeCount = before.Count,
                AfterCount = after.Count,
                AddedCount = after.Count(delegate(string key) { return !before.Contains(key); }),
                RemovedCount = before.Count(delegate(string key) { return !after.Contains(key); })
            };
        }

        private static HashSet<string> PolicyAccessKeys(string policyJson)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
            Dictionary<string, object> root = serializer.DeserializeObject(policyJson) as Dictionary<string, object>;
            if (root == null) throw new InvalidDataException("Корень allow.json должен быть объектом.");

            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            object assignmentsValue;
            IList assignments = root.TryGetValue("userAssignments", out assignmentsValue)
                ? assignmentsValue as IList : null;
            if (assignments == null) throw new InvalidDataException("В allow.json отсутствует массив userAssignments.");

            for (int assignmentIndex = 0; assignmentIndex < assignments.Count; assignmentIndex++)
            {
                Dictionary<string, object> assignment = assignments[assignmentIndex] as Dictionary<string, object>;
                if (assignment == null) continue;
                List<string> principals = new List<string>();
                AddPolicyPrincipals(principals, assignment, "users", "user:");
                AddPolicyPrincipals(principals, assignment, "groups", "group:");
                if (principals.Count == 0) principals.Add("assignment:" + assignmentIndex);

                object rulesValue;
                IList rules = assignment.TryGetValue("allowedDevices", out rulesValue)
                    ? rulesValue as IList : null;
                if (rules == null) continue;
                foreach (object ruleValue in rules)
                {
                    Dictionary<string, object> rule = ruleValue as Dictionary<string, object>;
                    object endpointValue;
                    string endpoint = rule != null && rule.TryGetValue("endpoint", out endpointValue)
                        ? Convert.ToString(endpointValue, CultureInfo.InvariantCulture) : "";
                    if (String.IsNullOrWhiteSpace(endpoint)) continue;
                    foreach (string principal in principals) result.Add(principal + "\u001f" + endpoint.Trim());
                }
            }
            return result;
        }

        private static void AddPolicyPrincipals(
            List<string> target, Dictionary<string, object> assignment, string propertyName, string prefix)
        {
            object value;
            IList principals = assignment.TryGetValue(propertyName, out value) ? value as IList : null;
            if (principals == null) return;
            foreach (object principalValue in principals)
            {
                string principal = Convert.ToString(principalValue, CultureInfo.InvariantCulture);
                if (!String.IsNullOrWhiteSpace(principal)) target.Add(prefix + principal.Trim());
            }
        }

        private async Task ImportPolicyAsync()
        {
            ClientSummary client = SelectedClient();
            if (client == null) return;

            string path;
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "Выберите резервный allow.json";
                dialog.Filter = "Политика DistControl (allow.json;*.json)|allow.json;*.json|Все файлы (*.*)|*.*";
                dialog.CheckFileExists = true;
                dialog.Multiselect = false;
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                path = dialog.FileName;
            }

            SetBusy(true, "Проверяем резервную политику для " + client.MachineName + "…");
            try
            {
                string imported = File.ReadAllText(path, Encoding.UTF8);
                PolicyResponse current = await Task.Run(delegate
                {
                    return api.Json<PolicyResponse>("GET", "/api/v1/admin/clients/" + client.Id + "/policy", null);
                });
                PolicyChangeSummary summary = SummarizePolicyChange(current.PolicyJson, imported);
                string message =
                    "Восстановить выбранный allow.json на компьютере «" + client.MachineName + "»?\r\n\r\n" +
                    "Разрешений сейчас: " + summary.BeforeCount + "\r\n" +
                    "Разрешений будет: " + summary.AfterCount + "\r\n" +
                    "Добавится: " + summary.AddedCount + "\r\n" +
                    "Удалится: " + summary.RemovedCount + "\r\n\r\n" +
                    "Файл: " + path;
                if (MessageBox.Show(this, message, "Восстановление политики",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

                if (summary.IsMassExpansion && MessageBox.Show(this,
                    "Резервный файл массово расширяет доступ: добавляется " + summary.AddedCount +
                    " токенов. Подтвердите это изменение отдельно.",
                    "Подтверждение массового изменения", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

                PolicyUpdateRequest request = new PolicyUpdateRequest
                {
                    ExpectedRevision = current.Revision,
                    PolicyJson = imported,
                    ConfirmMassExpansion = summary.IsMassExpansion
                };
                SetBusy(true, "Восстанавливаем политику на сервере…");
                await Task.Run(delegate
                {
                    api.Json<PolicyResponse>("PUT", "/api/v1/admin/clients/" + client.Id + "/policy", request);
                });
                await RefreshClientsAsync();
                SetOperationResult("Резервный allow.json сохранён на сервере и ожидает применения клиентом.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task RefreshLogsAsync()
        {
            RequireApi();
            ClientSummary client = SelectedClient();
            if (client == null) return;
            SetBusy(true, "Формируем журнал использования токенов на " + client.MachineName + "…");
            try
            {
                CaptureGridLayout(logsGrid, "logs");
                List<CentralLogRecord> records = await Task.Run(delegate
                {
                    return api.Json<List<CentralLogRecord>>("GET",
                        "/api/v1/admin/logs?clientId=" + Uri.EscapeDataString(client.Id) + "&limit=5000", null);
                });
                List<TokenSession> sessions = await Task.Run(delegate
                {
                    List<TokenSession> built = BuildTokenSessions(records ?? new List<CentralLogRecord>(), client.MachineName);
                    ResolveEmployeeNames(built);
                    return built;
                });
                logsGrid.DataSource = sessions.Select(delegate(TokenSession session)
                {
                    return new
                    {
                        Сотрудник = session.Employee,
                        Учётная_запись = session.User,
                        Компьютер = session.Computer,
                        Токен = session.Token,
                        Endpoint = session.Endpoint,
                        Подключён = SessionTime(session.Connected),
                        Отключён = SessionTime(session.Disconnected),
                        Длительность = SessionDuration(session),
                        Сеть = session.Network,
                        Состояние = session.Status
                    };
                }).ToList();
                FormatGrid(logsGrid, "logs");
                if (logsPage != null) tabs.SelectedTab = logsPage;
                SetOperationResult("Журнал токенов сформирован: " + sessions.Count + " операций/сеансов.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private static List<TokenSession> BuildTokenSessions(List<CentralLogRecord> records, string computer)
        {
            List<TokenAuditEvent> events = records
                .Where(delegate(CentralLogRecord item)
                {
                    return (item.FileName ?? "").StartsWith("audit-", StringComparison.OrdinalIgnoreCase);
                })
                .Select(delegate(CentralLogRecord item) { return ParseTokenAuditEvent(item.Text); })
                .Where(delegate(TokenAuditEvent item) { return item != null; })
                .OrderBy(delegate(TokenAuditEvent item) { return item.Timestamp; })
                .ToList();
            List<TokenSession> result = new List<TokenSession>();
            Dictionary<string, TokenSession> open = new Dictionary<string, TokenSession>(StringComparer.OrdinalIgnoreCase);
            foreach (TokenAuditEvent item in events)
            {
                string key = item.User + "\n" + item.Endpoint;
                bool connected = String.Equals(item.Action, "USE", StringComparison.OrdinalIgnoreCase);
                bool disconnected = IsDisconnectAction(item.Action);
                bool success = String.Equals(item.Result, "OK", StringComparison.OrdinalIgnoreCase);
                if (connected && success)
                {
                    TokenSession previous;
                    if (open.TryGetValue(key, out previous))
                    {
                        previous.Status = "Нет записи об отключении";
                        result.Add(previous);
                    }
                    open[key] = NewSession(item, computer, "Подключён");
                    continue;
                }
                if (connected && !success)
                {
                    TokenSession failed = NewSession(item, computer, "Ошибка подключения");
                    failed.Connected = item.Timestamp;
                    result.Add(failed);
                    continue;
                }
                if (!disconnected) continue;
                if (!success)
                {
                    TokenSession failed = NewSession(item, computer, "Ошибка отключения");
                    failed.Disconnected = item.Timestamp;
                    result.Add(failed);
                    continue;
                }
                TokenSession session;
                if (open.TryGetValue(key, out session))
                {
                    open.Remove(key);
                    session.Disconnected = item.Timestamp;
                    session.Status = "Завершён";
                    result.Add(session);
                }
                else
                {
                    session = NewSession(item, computer, "Отключён, подключение было раньше");
                    session.Disconnected = item.Timestamp;
                    result.Add(session);
                }
            }
            foreach (TokenSession session in open.Values)
            {
                session.Status = "Подключён, отключение не зафиксировано";
                result.Add(session);
            }
            return result.OrderByDescending(delegate(TokenSession item)
            {
                return item.Disconnected ?? item.Connected ?? DateTime.MinValue;
            }).ToList();
        }

        private static TokenSession NewSession(TokenAuditEvent item, string computer, string status)
        {
            return new TokenSession
            {
                User = item.User,
                Employee = item.User,
                Computer = computer ?? "",
                Endpoint = item.Endpoint,
                Token = String.IsNullOrWhiteSpace(item.Token) ? item.Endpoint : item.Token,
                Product = item.Product,
                Connected = String.Equals(item.Action, "USE", StringComparison.OrdinalIgnoreCase)
                    ? (DateTime?)item.Timestamp : null,
                Network = NetworkDescription(item.Details),
                Status = status
            };
        }

        private static bool IsDisconnectAction(string action)
        {
            return String.Equals(action, "STOP USING OWN", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(action, "AUTO STOP", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(action, "AUTO STOP BEFORE VPN SWITCH", StringComparison.OrdinalIgnoreCase);
        }

        private static TokenAuditEvent ParseTokenAuditEvent(string line)
        {
            List<string> fields = ParseCsvLine(line ?? "");
            if (fields.Count < 9 || String.Equals(fields[0], "timestamp", StringComparison.OrdinalIgnoreCase)) return null;
            DateTime timestamp;
            if (!DateTime.TryParseExact(fields[0], "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal, out timestamp) &&
                !DateTime.TryParse(fields[0], CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out timestamp)) return null;
            return new TokenAuditEvent
            {
                Timestamp = timestamp,
                User = fields[1],
                Action = fields[3],
                Endpoint = fields[4],
                Token = fields[5],
                Product = fields[6],
                Result = fields[7],
                Details = fields[8]
            };
        }

        private static List<string> ParseCsvLine(string line)
        {
            List<string> fields = new List<string>();
            StringBuilder current = new StringBuilder();
            bool quoted = false;
            for (int index = 0; index < line.Length; ++index)
            {
                char value = line[index];
                if (value == '"')
                {
                    if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                    {
                        current.Append('"');
                        index++;
                    }
                    else quoted = !quoted;
                }
                else if (value == ',' && !quoted)
                {
                    fields.Add(current.ToString());
                    current.Clear();
                }
                else current.Append(value);
            }
            fields.Add(current.ToString());
            return fields;
        }

        private void ResolveEmployeeNames(List<TokenSession> sessions)
        {
            foreach (string user in sessions.Select(delegate(TokenSession item) { return item.User; })
                .Where(delegate(string value) { return !String.IsNullOrWhiteSpace(value); })
                .Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string displayName;
                if (!employeeNameCache.TryGetValue(user, out displayName))
                {
                    displayName = ResolveEmployeeName(user);
                    employeeNameCache[user] = displayName;
                }
                foreach (TokenSession session in sessions.Where(delegate(TokenSession item)
                {
                    return String.Equals(item.User, user, StringComparison.OrdinalIgnoreCase);
                })) session.Employee = displayName;
            }
        }

        private static string ResolveEmployeeName(string account)
        {
            try
            {
                string domain = "";
                string login = account;
                int separator = account.IndexOf('\\');
                if (separator > 0)
                {
                    domain = account.Substring(0, separator);
                    login = account.Substring(separator + 1);
                }
                using (PrincipalContext context = String.IsNullOrWhiteSpace(domain)
                    ? new PrincipalContext(ContextType.Domain)
                    : new PrincipalContext(ContextType.Domain, domain))
                using (UserPrincipal principal = UserPrincipal.FindByIdentity(
                    context, IdentityType.SamAccountName, login))
                {
                    if (principal != null && !String.IsNullOrWhiteSpace(principal.DisplayName))
                        return principal.DisplayName;
                }
            }
            catch { }
            return account;
        }

        private static string NetworkDescription(string details)
        {
            string profile = DetailValue(details, "profileName");
            string address = DetailValue(details, "publicIp");
            if (String.Equals(address, "unknown", StringComparison.OrdinalIgnoreCase)) address = "";
            if (String.IsNullOrWhiteSpace(profile)) return address;
            return String.IsNullOrWhiteSpace(address) ? profile : profile + " / IP " + address;
        }

        private static string DetailValue(string details, string name)
        {
            foreach (string part in (details ?? "").Split(';'))
            {
                string value = part.Trim();
                int separator = value.IndexOf('=');
                if (separator > 0 && String.Equals(value.Substring(0, separator).Trim(), name,
                    StringComparison.OrdinalIgnoreCase)) return value.Substring(separator + 1).Trim();
            }
            return "";
        }

        private static string SessionTime(DateTime? value)
        {
            return value.HasValue ? value.Value.ToString("dd.MM.yyyy HH:mm:ss") : "—";
        }

        private static string SessionDuration(TokenSession session)
        {
            if (!session.Connected.HasValue || !session.Disconnected.HasValue) return "—";
            TimeSpan duration = session.Disconnected.Value - session.Connected.Value;
            if (duration < TimeSpan.Zero) return "—";
            return duration.TotalDays >= 1
                ? ((int)duration.TotalDays) + " д. " + duration.ToString("hh\\:mm\\:ss")
                : duration.ToString("hh\\:mm\\:ss");
        }

        private async Task RefreshAuditAsync()
        {
            RequireApi();
            SetBusy(true, "Загружаем историю изменений…");
            try
            {
                CaptureGridLayout(auditGrid, "audit");
                List<AuditRecord> records = await Task.Run(delegate
                {
                    return api.Json<List<AuditRecord>>("GET", "/api/v1/admin/audit?limit=1000", null);
                });
                auditGrid.DataSource = (records ?? new List<AuditRecord>()).Select(delegate(AuditRecord x)
                {
                    return new { Время = LocalTime(x.TimestampUtc), Администратор = x.Actor, Действие = x.Action, Объект = x.Target, Подробности = x.Details };
                }).ToList();
                FormatGrid(auditGrid, "audit");
                SetOperationResult("История изменений загружена: " + (records == null ? 0 : records.Count) + " записей.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task PublishUpdateAsync()
        {
            RequireApi();
            string version = updateVersion.Text.Trim();
            string path = updatePath.Text.Trim();
            if (version.Length == 0 || !File.Exists(path))
            {
                MessageBox.Show(this, "Укажите версию и существующий ZIP-пакет.", "DistControl", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string packageVersion;
            try { packageVersion = ReadUpdatePackageVersion(path); }
            catch (Exception error) { ShowError(error); return; }
            if (!String.Equals(version, packageVersion, StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show(this,
                    "В поле указана версия «" + version + "», а внутри ZIP находится версия «" + packageVersion +
                    "». Выберите пакет заново или исправьте номер версии.",
                    "DistControl", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            SetBusy(true, "Подготавливаем обновление " + version + " к загрузке…", true);
            try
            {
                await Task.Run(delegate
                {
                    api.UploadUpdate(version, path, delegate(int percent) { ReportUploadProgress(version, percent); });
                });
                SetOperationResult("Обновление " + version + " опубликовано на сервере.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private async Task AssignUpdateAsync()
        {
            RequireApi();
            List<ClientSummary> selectedClients = SelectedUpdateClients();
            if (selectedClients.Count == 0) return;
            string version = updateVersion.Text.Trim();
            if (version.Length == 0)
            {
                MessageBox.Show(this, "Укажите опубликованную версию.", "DistControl", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            SetBusy(true, "Назначаем обновление " + version + " выбранным компьютерам…");
            try
            {
                UpdateAssignmentRequest request = new UpdateAssignmentRequest { Version = version };
                await Task.Run(delegate
                {
                    foreach (ClientSummary client in selectedClients)
                        api.Json<object>("POST", "/api/v1/admin/clients/" + client.Id + "/update", request);
                });
                await RefreshUpdateClientsAsync();
                SetOperationResult("Обновление " + version + " назначено компьютерам: " + selectedClients.Count +
                    ". Дальнейшие этапы автоматически отображаются в таблице.");
            }
            catch (Exception error) { ShowError(error); }
            finally { SetBusy(false, null); }
        }

        private List<ClientSummary> SelectedUpdateClients()
        {
            List<ClientSummary> result = new List<ClientSummary>();
            if (!updateClientsGrid.Columns.Contains("Id")) return result;
            foreach (DataGridViewRow row in updateClientsGrid.SelectedRows)
            {
                string id = Convert.ToString(row.Cells["Id"].Value);
                ClientSummary client = clients.FirstOrDefault(delegate(ClientSummary c) { return c.Id == id; });
                if (client != null && !result.Any(delegate(ClientSummary c) { return c.Id == client.Id; })) result.Add(client);
            }
            if (result.Count == 0)
                MessageBox.Show(this, "Выберите один или несколько компьютеров в таблице на вкладке «Обновления».",
                    "DistControl", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return result;
        }

        private ClientSummary SelectedClient()
        {
            if (clientsGrid.CurrentRow == null)
            {
                MessageBox.Show(this, "Выберите компьютер на вкладке «Компьютеры».", "DistControl", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return null;
            }
            string id = Convert.ToString(clientsGrid.CurrentRow.Cells["Id"].Value);
            return clients.FirstOrDefault(delegate(ClientSummary c) { return c.Id == id; });
        }

        private void LoadSettings()
        {
            try
            {
                string path = File.Exists(settingsPath) ? settingsPath : legacySettingsPath;
                if (!File.Exists(path)) return;
                AdminSettings settings = json.Deserialize<AdminSettings>(File.ReadAllText(path, Encoding.UTF8));
                if (settings == null) return;
                serverText.Text = settings.ServerUrl;
                gridLayouts = settings.GridLayouts ?? new Dictionary<string, List<GridColumnLayout>>();
            }
            catch { }
        }

        private void SaveSettings()
        {
            CaptureGridLayout(clientsGrid, "clients");
            CaptureGridLayout(enrollmentsGrid, "enrollments");
            CaptureGridLayout(updateClientsGrid, "updates");
            CaptureGridLayout(logsGrid, "logs");
            CaptureGridLayout(auditGrid, "audit");
            Directory.CreateDirectory(Path.GetDirectoryName(settingsPath));
            AdminSettings settings = new AdminSettings
            {
                ServerUrl = serverText.Text.Trim(),
                GridLayouts = gridLayouts
            };
            File.WriteAllText(settingsPath, json.Serialize(settings), Encoding.UTF8);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            updateStatusTimer.Stop();
            try { SaveSettings(); } catch { }
            base.OnFormClosing(e);
        }

        private static DataGridView NewGrid()
        {
            return new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToOrderColumns = true,
                AllowUserToResizeColumns = true,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                RowHeadersVisible = false,
                BackgroundColor = SystemColors.Window,
                BorderStyle = BorderStyle.Fixed3D
            };
        }

        private void FormatGrid(DataGridView grid, string key)
        {
            if (grid.Columns.Contains("Id")) grid.Columns["Id"].Visible = false;
            foreach (DataGridViewColumn column in grid.Columns)
            {
                column.SortMode = DataGridViewColumnSortMode.Automatic;
                column.Resizable = DataGridViewTriState.True;
                column.AutoSizeMode = DataGridViewAutoSizeColumnMode.None;
            }

            List<GridColumnLayout> layout;
            if (!gridLayouts.TryGetValue(key, out layout) || layout == null || layout.Count == 0)
            {
                grid.AutoResizeColumns(DataGridViewAutoSizeColumnsMode.DisplayedCells);
                foreach (DataGridViewColumn column in grid.Columns)
                    if (column.Visible) column.Width = Math.Max(70, Math.Min(420, column.Width));
                return;
            }

            applyingGridLayout = true;
            try
            {
                foreach (GridColumnLayout item in layout)
                {
                    if (!grid.Columns.Contains(item.Name)) continue;
                    DataGridViewColumn column = grid.Columns[item.Name];
                    column.Width = Math.Max(40, Math.Min(800, item.Width));
                }
                foreach (GridColumnLayout item in layout.OrderBy(delegate(GridColumnLayout x) { return x.DisplayIndex; }))
                {
                    if (!grid.Columns.Contains(item.Name)) continue;
                    try { grid.Columns[item.Name].DisplayIndex = Math.Max(0, Math.Min(grid.Columns.Count - 1, item.DisplayIndex)); }
                    catch { }
                }
            }
            finally { applyingGridLayout = false; }
        }

        private void CaptureGridLayout(DataGridView grid, string key)
        {
            if (applyingGridLayout || grid.Columns.Count == 0) return;
            List<GridColumnLayout> layout = new List<GridColumnLayout>();
            foreach (DataGridViewColumn column in grid.Columns)
            {
                layout.Add(new GridColumnLayout
                {
                    Name = column.Name,
                    DisplayIndex = column.DisplayIndex,
                    Width = column.Width
                });
            }
            gridLayouts[key] = layout;
        }

        private void SetBusy(bool busy, string text, bool determinate = false)
        {
            connectButton.Enabled = !busy;
            publishButton.Enabled = !busy;
            assignButton.Enabled = !busy;
            UseWaitCursor = busy;
            operationProgress.Visible = busy;
            if (busy)
            {
                operationPanel.BackColor = Color.AliceBlue;
                operationProgress.Style = determinate ? ProgressBarStyle.Continuous : ProgressBarStyle.Marquee;
                operationProgress.MarqueeAnimationSpeed = determinate ? 0 : 25;
                operationProgress.Value = 0;
            }
            if (!String.IsNullOrWhiteSpace(text))
            {
                operationLabel.Text = text;
                statusLabel.Text = text;
            }
        }

        private void ReportUploadProgress(string version, int percent)
        {
            if (IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke((MethodInvoker)delegate { ReportUploadProgress(version, percent); });
                return;
            }
            int value = Math.Max(0, Math.Min(100, percent));
            operationProgress.Style = ProgressBarStyle.Continuous;
            operationProgress.Value = value;
            string text = value < 100
                ? "Загружаем обновление " + version + " на сервер: " + value + "%"
                : "Файл загружен на 100%. Сервер проверяет и сохраняет пакет…";
            operationLabel.Text = text;
            statusLabel.Text = text;
        }

        private void SetOperationResult(string text, bool error = false)
        {
            operationProgress.Visible = false;
            operationPanel.BackColor = error ? Color.MistyRose : Color.Honeydew;
            operationLabel.Text = text;
            statusLabel.Text = text;
        }

        private void RequireApi()
        {
            if (api == null) throw new InvalidOperationException("Сначала подключитесь к серверу.");
        }

        private void ShowError(Exception error)
        {
            string message = HumanError(error);
            SetOperationResult(message, true);
            MessageBox.Show(this, message, "DistControl", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private static string HumanError(Exception error)
        {
            WebException web = error as WebException;
            if (web != null)
            {
                HttpWebResponse response = web.Response as HttpWebResponse;
                if (response != null)
                {
                    try
                    {
                        using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                            return "Сервер отклонил запрос: " + reader.ReadToEnd();
                    }
                    catch { }
                }
                return "Сервер DistControl недоступен: " + web.Message;
            }
            return error.Message;
        }

        private static string LocalTime(string value)
        {
            DateTime parsed;
            return DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.RoundtripKind, out parsed)
                ? parsed.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss") : value;
        }

        private static bool VersionsEquivalent(string left, string right)
        {
            if (String.Equals(left, right, StringComparison.OrdinalIgnoreCase)) return true;
            Version leftVersion;
            Version rightVersion;
            if (!Version.TryParse(left, out leftVersion) || !Version.TryParse(right, out rightVersion)) return false;
            return VersionComponent(leftVersion.Major) == VersionComponent(rightVersion.Major) &&
                VersionComponent(leftVersion.Minor) == VersionComponent(rightVersion.Minor) &&
                VersionComponent(leftVersion.Build) == VersionComponent(rightVersion.Build) &&
                VersionComponent(leftVersion.Revision) == VersionComponent(rightVersion.Revision);
        }

        private static int VersionComponent(int value)
        {
            return value < 0 ? 0 : value;
        }

        private static string ActorName()
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }

        private static string Protect(string value)
        {
            if (String.IsNullOrEmpty(value)) return "";
            return Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.CurrentUser));
        }

        private static string Unprotect(string value)
        {
            if (String.IsNullOrEmpty(value)) return "";
            try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(value), null, DataProtectionScope.CurrentUser)); }
            catch { return ""; }
        }

        private static string Sha256(byte[] value)
        {
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(value)).Replace("-", "");
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
