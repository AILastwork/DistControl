using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

[assembly: AssemblyTitle("DistControl Central Agent")]
[assembly: AssemblyProduct("DistControl")]
[assembly: AssemblyVersion("0.8.13.0")]
[assembly: AssemblyFileVersion("0.8.13.0")]

namespace DistControl.Agent
{
    public sealed class AgentConfig
    {
        public string ServerUrl = "";
        public string ProtectedEnrollmentRequestToken = "";
        public string ClientId = "";
        public string ProtectedClientToken = "";
        public string TargetUser = "";
        public string PolicyPath = "";
        public string LogsDirectory = "";
        public string NetworkStatePath = "";
        public string InstallDirectory = "";
        public int PollSeconds = 30;
        public bool AutoUpdate = true;
        public string AppliedHubRevision = "";
        public string HubStatus = "";
        public string LastAppliedPolicyRevision = "";
    }

    public sealed class EnrollRequest
    {
        public string RequestToken = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string PolicyJson = "";
    }

    public sealed class EnrollResponse
    {
        public bool Approved = false;
        public bool Rejected = false;
        public string RequestId = "";
        public string Status = "";
        public string ClientId = "";
        public string ClientToken = "";
        public string PolicyRevision = "";
    }

    public sealed class HeartbeatRequest
    {
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string AppliedPolicyRevision = "";
        public string UpdateStatus = "";
        public string LastError = "";
        public string NetworkStateJson = "";
        public string CurrentManualHubs = "";
        public string AppliedHubRevision = "";
        public string HubStatus = "";
    }

    public sealed class PolicyResponse
    {
        public string Revision = "";
        public string PolicyJson = "";
    }

    public sealed class HubConfiguration
    {
        public string Revision = "";
        public string ManualHubs = "";
        public string UpdatedUtc = "";
        public string UpdatedBy = "";
    }

    public sealed class LogUploadRequest
    {
        public List<LogUploadItem> Items = new List<LogUploadItem>();
    }

    public sealed class LogUploadItem
    {
        public string Id = "";
        public string FileName = "";
        public string Text = "";
    }

    public sealed class UpdateManifestResponse
    {
        public bool Available = false;
        public string Version = "";
        public string Sha256 = "";
        public long Size = 0;
        public string DownloadPath = "";
    }

    public sealed class UpdatePackageManifest
    {
        public string Version = "";
        public List<UpdatePackageFile> Files = new List<UpdatePackageFile>();
    }

    public sealed class UpdatePackageFile
    {
        public string Path = "";
        public string Sha256 = "";
    }

    public sealed class ClientCommandResponse
    {
        public bool Available = false;
        public string Id = "";
        public string Type = "";
    }

    public sealed class ClientCommandResultRequest
    {
        public bool Success = false;
        public string Message = "";
    }

    internal sealed class AgentWorker
    {
        private readonly string configPath;
        private readonly string logPath;
        private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
        private AgentConfig config;
        private string token = "";
        private string enrollmentRequestToken = "";
        private string lastEnrollmentStatus = "";
        private string appliedRevision = "";
        private string updateStatus = "";
        private string lastError = "";
        private string reportedPolicyConflictRevision = "";
        private bool missingServerWasLogged;

        public AgentWorker(string configPath)
        {
            this.configPath = Path.GetFullPath(configPath);
            logPath = Path.Combine(Path.GetDirectoryName(this.configPath), "agent.log");
        }

        public int PollSeconds { get { return config == null ? 30 : Math.Max(5, Math.Min(300, config.PollSeconds)); } }

        public void Initialize()
        {
            config = LoadConfig();
            token = Unprotect(config.ProtectedClientToken);
            enrollmentRequestToken = Unprotect(config.ProtectedEnrollmentRequestToken);
            appliedRevision = Revision(ReadText(config.PolicyPath));
            ReadUpdateResult();
        }

        public void RunOnce()
        {
            if (config == null) Initialize();
            if (String.IsNullOrWhiteSpace(config.ServerUrl))
            {
                if (!missingServerWasLogged)
                {
                    Log("Центральный сервер не настроен. Агент ожидает заполнения agent.json.");
                    missingServerWasLogged = true;
                }
                return;
            }

            try
            {
                if (!EnsureEnrolled()) return;
                SendHeartbeat();
                ProcessPendingCommand();
                SynchronizePolicy();
                SynchronizeHubs();
                UploadLogs();
                CheckUpdate();
                lastError = "";
            }
            catch (Exception error)
            {
                lastError = HumanError(error);
                Log(lastError);
            }
        }

        private bool EnsureEnrolled()
        {
            if (!String.IsNullOrWhiteSpace(config.ClientId) && !String.IsNullOrWhiteSpace(token)) return true;
            if (String.IsNullOrWhiteSpace(enrollmentRequestToken))
            {
                enrollmentRequestToken = RandomToken(32);
                config.ProtectedEnrollmentRequestToken = Protect(enrollmentRequestToken);
                SaveConfig();
            }

            EnrollRequest request = new EnrollRequest
            {
                RequestToken = enrollmentRequestToken,
                MachineName = Environment.MachineName,
                UserName = config.TargetUser,
                AppVersion = AppVersion(),
                AgentVersion = AgentVersion(),
                PolicyJson = ReadText(config.PolicyPath)
            };
            EnrollResponse response = SendJson<EnrollResponse>("POST", "/api/v1/enroll", request, false);
            if (response == null || !response.Approved || String.IsNullOrWhiteSpace(response.ClientToken))
            {
                string status = response == null || String.IsNullOrWhiteSpace(response.Status)
                    ? "Заявка отправлена и ожидает подтверждения администратора домена."
                    : response.Status;
                if (!String.Equals(lastEnrollmentStatus, status, StringComparison.Ordinal))
                {
                    Log(status);
                    lastEnrollmentStatus = status;
                }
                return false;
            }
            config.ClientId = response.ClientId;
            token = response.ClientToken;
            config.ProtectedClientToken = Protect(token);
            config.ProtectedEnrollmentRequestToken = "";
            enrollmentRequestToken = "";
            SaveConfig();
            Log("Компьютер зарегистрирован на сервере. Идентификатор: " + config.ClientId + ".");
            return true;
        }

        private void SendHeartbeat()
        {
            HeartbeatRequest heartbeat = new HeartbeatRequest
            {
                MachineName = Environment.MachineName,
                UserName = config.TargetUser,
                AppVersion = AppVersion(),
                AgentVersion = AgentVersion(),
                AppliedPolicyRevision = appliedRevision,
                UpdateStatus = updateStatus,
                LastError = lastError,
                NetworkStateJson = ReadText(config.NetworkStatePath),
                CurrentManualHubs = ReadCurrentManualHubs(),
                AppliedHubRevision = config.AppliedHubRevision,
                HubStatus = config.HubStatus
            };
            SendJson<object>("POST", "/api/v1/client/heartbeat", heartbeat, true);
        }

        private void SynchronizePolicy()
        {
            PolicyResponse policy = SendJson<PolicyResponse>("GET", "/api/v1/client/policy", null, true);
            if (String.IsNullOrWhiteSpace(policy.Revision)) return;
            if (String.Equals(policy.Revision, appliedRevision, StringComparison.Ordinal))
            {
                if (!String.Equals(config.LastAppliedPolicyRevision, policy.Revision, StringComparison.Ordinal))
                {
                    config.LastAppliedPolicyRevision = policy.Revision;
                    SaveConfig();
                }
                return;
            }
            if (!String.IsNullOrWhiteSpace(config.LastAppliedPolicyRevision) &&
                String.Equals(policy.Revision, config.LastAppliedPolicyRevision, StringComparison.Ordinal))
            {
                string conflict = config.LastAppliedPolicyRevision + ":" + appliedRevision;
                if (!String.Equals(reportedPolicyConflictRevision, conflict, StringComparison.Ordinal))
                {
                    Log("Локальный allow.json изменён после последней синхронизации. Серверная копия не менялась, поэтому агент не перезаписывает локальные назначения. Сохраните нужный файл через центральную админку.");
                    reportedPolicyConflictRevision = conflict;
                }
                return;
            }
            ValidatePolicy(policy.PolicyJson);
            AtomicWrite(config.PolicyPath, Encoding.UTF8.GetBytes(policy.PolicyJson));
            appliedRevision = policy.Revision;
            config.LastAppliedPolicyRevision = policy.Revision;
            SaveConfig();
            reportedPolicyConflictRevision = "";
            Log("Получена и применена новая политика " + appliedRevision + ".");
        }

        private void ProcessPendingCommand()
        {
            ClientCommandResponse command = SendJson<ClientCommandResponse>(
                "GET", "/api/v1/client/command", null, true);
            if (command == null || !command.Available || String.IsNullOrWhiteSpace(command.Id)) return;

            ClientCommandResultRequest result = new ClientCommandResultRequest();
            try
            {
                if (!String.Equals(command.Type, "FORCE_DISCONNECT", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Сервер прислал неизвестную команду: " + command.Type + ".");
                result.Message = ForceDisconnectTokens();
                result.Success = true;
                Log("Команда администратора выполнена. " + result.Message);
            }
            catch (Exception error)
            {
                result.Success = false;
                result.Message = HumanError(error);
                Log("Команда администратора не выполнена. " + result.Message);
            }
            SendJson<object>("POST", "/api/v1/client/command/" +
                Uri.EscapeDataString(command.Id) + "/result", result, true);
        }

        private string ForceDisconnectTokens()
        {
            string executable = Path.Combine(config.InstallDirectory, "DistControl.exe");
            if (!File.Exists(executable))
                throw new FileNotFoundException("Не найден клиент DistControl.exe.", executable);
            if (String.IsNullOrWhiteSpace(config.TargetUser))
                throw new InvalidOperationException("В конфигурации агента не указан пользователь компьютера.");

            string resultPath = Path.Combine(Path.GetTempPath(),
                "DistControl-force-disconnect-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                string arguments = "--force-disconnect-all --policy " + QuoteArgument(config.PolicyPath) +
                    " --target-user " + QuoteArgument(config.TargetUser) + " --result " + QuoteArgument(resultPath);
                ProcessStartInfo start = new ProcessStartInfo(executable, arguments);
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
                using (Process process = Process.Start(start))
                {
                    if (!process.WaitForExit(120000))
                    {
                        try { process.Kill(); } catch { }
                        throw new System.TimeoutException("Отключение токенов не завершилось за две минуты.");
                    }
                    string message = File.Exists(resultPath)
                        ? File.ReadAllText(resultPath, Encoding.UTF8).Trim()
                        : "Клиент не записал результат команды.";
                    if (process.ExitCode != 0) throw new InvalidOperationException(message);
                    return String.IsNullOrWhiteSpace(message) ? "Токены отключены." : message;
                }
            }
            finally
            {
                try { if (File.Exists(resultPath)) File.Delete(resultPath); } catch { }
            }
        }

        private static string QuoteArgument(string value)
        {
            return "\"" + (value ?? "").Replace("\"", "\\\"") + "\"";
        }

        private void SynchronizeHubs()
        {
            HubConfiguration hubs = SendJson<HubConfiguration>("GET", "/api/v1/client/hubs", null, true);
            if (hubs == null || String.IsNullOrWhiteSpace(hubs.Revision) ||
                String.Equals(hubs.Revision, config.AppliedHubRevision, StringComparison.Ordinal)) return;

            try
            {
                List<string> addresses = ValidateHubEndpoints(hubs.ManualHubs);
                UpdateManualHubs(Path.Combine(config.InstallDirectory, "dkcl.ini"), hubs.ManualHubs ?? "");
                ApplyHubRoutes(addresses);
                RestartDkClient();
                config.AppliedHubRevision = hubs.Revision;
                config.HubStatus = "USB-серверы применены: " + addresses.Count + ".";
                SaveConfig();
                Log(config.HubStatus);
                TrySendHeartbeat();
            }
            catch (Exception error)
            {
                config.HubStatus = "Не удалось применить USB-серверы: " + HumanError(error);
                SaveConfig();
                TrySendHeartbeat();
                throw;
            }
        }

        private static List<string> ValidateHubEndpoints(string manualHubs)
        {
            List<string> addresses = new List<string>();
            string[] entries = (manualHubs ?? "").Split(
                new[] { ',', ';', '\r', '\n', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string raw in entries)
            {
                string entry = raw.Trim();
                int separator = entry.LastIndexOf(':');
                string addressText = separator < 0 ? entry : entry.Substring(0, separator);
                string portText = separator < 0 ? "6565" : entry.Substring(separator + 1);
                IPAddress address;
                int port;
                if (!IPAddress.TryParse(addressText, out address) ||
                    address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    throw new InvalidDataException("Некорректный IPv4-адрес USB-сервера: " + entry + ".");
                if (!Int32.TryParse(portText, out port) || port < 1 || port > 65535)
                    throw new InvalidDataException("Некорректный порт USB-сервера: " + entry + ".");
                string normalizedAddress = address.ToString();
                if (!addresses.Contains(normalizedAddress, StringComparer.OrdinalIgnoreCase))
                    addresses.Add(normalizedAddress);
            }
            return addresses;
        }

        private static void UpdateManualHubs(string iniPath, string manualHubs)
        {
            if (!File.Exists(iniPath)) throw new FileNotFoundException("Не найден файл dkcl.ini.", iniPath);
            List<string> lines = File.ReadAllLines(iniPath, Encoding.Default).ToList();
            bool inSettings = false;
            bool settingsFound = false;
            bool replaced = false;
            for (int index = 0; index < lines.Count; ++index)
            {
                string trimmed = lines[index].Trim();
                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    if (inSettings && !replaced)
                    {
                        lines.Insert(index, "ManualHubs=" + manualHubs);
                        replaced = true;
                        break;
                    }
                    inSettings = String.Equals(trimmed, "[Settings]", StringComparison.OrdinalIgnoreCase);
                    if (inSettings) settingsFound = true;
                    continue;
                }
                if (inSettings && trimmed.StartsWith("ManualHubs", StringComparison.OrdinalIgnoreCase) &&
                    trimmed.Contains("="))
                {
                    lines[index] = "ManualHubs=" + manualHubs;
                    replaced = true;
                    break;
                }
            }
            if (!replaced)
            {
                if (!settingsFound) lines.Add("[Settings]");
                lines.Add("ManualHubs=" + manualHubs);
            }
            AtomicWrite(iniPath, Encoding.Default.GetBytes(
                String.Join(Environment.NewLine, lines.ToArray()) + Environment.NewLine));
        }

        private string ReadCurrentManualHubs()
        {
            string iniPath = Path.Combine(config.InstallDirectory, "dkcl.ini");
            if (!File.Exists(iniPath)) return "";
            bool inSettings = false;
            foreach (string line in File.ReadAllLines(iniPath, Encoding.Default))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    inSettings = String.Equals(trimmed, "[Settings]", StringComparison.OrdinalIgnoreCase);
                    continue;
                }
                if (inSettings && trimmed.StartsWith("ManualHubs", StringComparison.OrdinalIgnoreCase))
                {
                    int separator = trimmed.IndexOf('=');
                    return separator < 0 ? "" : trimmed.Substring(separator + 1).Trim();
                }
            }
            return "";
        }

        private void ApplyHubRoutes(List<string> addresses)
        {
            string dataDirectory = Path.GetDirectoryName(config.PolicyPath);
            string manifestPath = Path.Combine(dataDirectory, "managed-hub-routes.json");
            Directory.CreateDirectory(dataDirectory);
            string desired = String.Join(",", addresses.Select(delegate(string value)
            {
                return "'" + value.Replace("'", "''") + "'";
            }).ToArray());
            string escapedManifest = manifestPath.Replace("'", "''");
            string script =
                "$ErrorActionPreference='Stop';" +
                "$desired=@(" + desired + ");$manifest='" + escapedManifest + "';" +
                "$old=@();if(Test-Path -LiteralPath $manifest){try{$old=@((Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json).routes)}catch{$old=@()}};" +
                "foreach($r in $old){if($r.destination -and $desired -notcontains [string]$r.destination){& route.exe delete ([string]$r.destination) mask 255.255.255.255 ([string]$r.gateway) if ([string]$r.interfaceIndex)|Out-Null}};" +
                "$physical=$null;if($desired.Count -gt 0){$physical=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop|Where-Object{$_.NextHop -and $_.NextHop -ne '0.0.0.0'}|Sort-Object RouteMetric|Where-Object{$a=Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue;$a -and $a.Status -eq 'Up' -and $a.HardwareInterface}|Select-Object -First 1;if(-not $physical){throw 'Не найден физический шлюз для маршрутов USB-серверов.'}};" +
                "$managed=@();foreach($ip in $desired){$exists=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix ($ip+'/32') -ErrorAction SilentlyContinue|Where-Object{$_.NextHop -eq $physical.NextHop -and $_.ifIndex -eq $physical.ifIndex});$was=@($old|Where-Object{$_.destination -eq $ip});if($exists.Count -eq 0){& route.exe -p add $ip mask 255.255.255.255 ([string]$physical.NextHop) metric 1 if ([string]$physical.ifIndex)|Out-Null;if($LASTEXITCODE -ne 0){throw ('Не удалось создать маршрут к '+$ip)}};if($exists.Count -eq 0 -or $was.Count -gt 0){$managed+=@{destination=$ip;gateway=[string]$physical.NextHop;interfaceIndex=[int]$physical.ifIndex}}};" +
                "@{version=1;createdAt=(Get-Date).ToString('o');routes=$managed}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $manifest -Encoding UTF8;";
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            ProcessStartInfo start = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded);
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            using (Process process = Process.Start(start))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                if (!process.WaitForExit(60000))
                {
                    try { process.Kill(); } catch { }
                    throw new System.TimeoutException("Настройка маршрутов USB-серверов не завершилась за 60 секунд.");
                }
                if (process.ExitCode != 0)
                    throw new InvalidOperationException(String.IsNullOrWhiteSpace(error) ? output : error);
            }
        }

        private static void RestartDkClient()
        {
            using (ServiceController service = new ServiceController("dkclient"))
            {
                service.Refresh();
                if (service.Status != ServiceControllerStatus.Stopped &&
                    service.Status != ServiceControllerStatus.StopPending)
                {
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
        }

        private void UploadLogs()
        {
            if (String.IsNullOrWhiteSpace(config.LogsDirectory) || !Directory.Exists(config.LogsDirectory)) return;
            LogUploadRequest request = new LogUploadRequest();
            foreach (string file in Directory.GetFiles(config.LogsDirectory)
                .Where(delegate(string path)
                {
                    string name = Path.GetFileName(path);
                    return name.StartsWith("audit-", StringComparison.OrdinalIgnoreCase) &&
                        String.Equals(Path.GetExtension(name), ".csv", StringComparison.OrdinalIgnoreCase);
                }).OrderByDescending(File.GetLastWriteTimeUtc).Take(6))
            {
                string[] lines;
                try { lines = File.ReadAllLines(file, Encoding.UTF8); }
                catch { continue; }
                int firstLine = Math.Max(0, lines.Length - 250);
                for (int lineIndex = firstLine; lineIndex < lines.Length; ++lineIndex)
                {
                    string line = lines[lineIndex];
                    if (String.IsNullOrWhiteSpace(line)) continue;
                    string id = Sha256(Path.GetFileName(file) + "\n" + lineIndex + "\n" + line).Substring(0, 32);
                    request.Items.Add(new LogUploadItem { Id = id, FileName = Path.GetFileName(file), Text = line });
                }
            }
            if (request.Items.Count > 0) SendJson<object>("POST", "/api/v1/client/logs", request, true);
        }

        private void CheckUpdate()
        {
            if (!config.AutoUpdate) return;
            UpdateManifestResponse manifest = SendJson<UpdateManifestResponse>("GET", "/api/v1/client/update", null, true);
            if (manifest == null || !manifest.Available || String.IsNullOrWhiteSpace(manifest.Version)) return;
            if (Process.GetProcessesByName("DistControl").Length > 0 ||
                Process.GetProcessesByName("DistControl.Admin").Length > 0)
            {
                ReportUpdateStatus("Обновление " + manifest.Version + " ожидает закрытия DistControl и локальной админки");
                return;
            }

            ReportUpdateStatus("Скачивается обновление " + manifest.Version + ": 0%");
            byte[] package = DownloadUpdatePackage(manifest);
            ReportUpdateStatus("Проверяется обновление " + manifest.Version);
            string actual = Sha256(package);
            if (!String.Equals(actual, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Контрольная сумма загруженного обновления не совпадает.");

            ReportUpdateStatus("Подготавливаются файлы обновления " + manifest.Version);
            string updateRoot = Path.Combine(Path.GetDirectoryName(configPath), "updates");
            string stage = Path.Combine(updateRoot, "stage-" + SafeName(manifest.Version));
            if (Directory.Exists(stage)) Directory.Delete(stage, true);
            Directory.CreateDirectory(stage);
            string zip = Path.Combine(updateRoot, "update-" + SafeName(manifest.Version) + ".zip");
            Directory.CreateDirectory(updateRoot);
            File.WriteAllBytes(zip, package);
            ZipFile.ExtractToDirectory(zip, stage);
            ValidateUpdateStage(stage, manifest.Version);

            string updater = Path.Combine(stage, "DistControl.Updater.exe");
            if (!File.Exists(updater)) updater = Path.Combine(config.InstallDirectory, "DistControl.Updater.exe");
            if (!File.Exists(updater)) throw new FileNotFoundException("В обновлении отсутствует DistControl.Updater.exe.");
            string temporaryUpdater = Path.Combine(Path.GetTempPath(), "DistControl.Updater-" + Guid.NewGuid().ToString("N") + ".exe");
            File.Copy(updater, temporaryUpdater, true);

            ReportUpdateStatus("Устанавливается обновление " + manifest.Version);
            ProcessStartInfo start = new ProcessStartInfo(temporaryUpdater,
                "--wait-pid " + Process.GetCurrentProcess().Id +
                " --staging \"" + stage + "\" --install \"" + config.InstallDirectory +
                "\" --service DistControlAgent --result \"" + Path.Combine(Path.GetDirectoryName(configPath), "update-result.json") + "\"");
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            Process.Start(start);
            Environment.Exit(0);
        }

        private void ValidateUpdateStage(string stage, string expectedVersion)
        {
            string manifestPath = Path.Combine(stage, "manifest.json");
            if (!File.Exists(manifestPath)) throw new InvalidDataException("В обновлении отсутствует manifest.json.");
            UpdatePackageManifest manifest = json.Deserialize<UpdatePackageManifest>(File.ReadAllText(manifestPath, Encoding.UTF8));
            if (manifest == null || !String.Equals(manifest.Version, expectedVersion, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Версия пакета обновления не совпадает с назначенной.");
            foreach (UpdatePackageFile item in manifest.Files ?? new List<UpdatePackageFile>())
            {
                string relative = item.Path.Replace('/', Path.DirectorySeparatorChar);
                string full = Path.GetFullPath(Path.Combine(stage, relative));
                if (!full.StartsWith(Path.GetFullPath(stage) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Пакет содержит недопустимый путь: " + item.Path);
                if (!File.Exists(full)) throw new FileNotFoundException("В пакете отсутствует файл " + item.Path + ".");
                if (!String.Equals(Sha256(File.ReadAllBytes(full)), item.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Повреждён файл обновления " + item.Path + ".");
            }
        }

        private T SendJson<T>(string method, string path, object body, bool authenticated)
        {
            byte[] bytes = body == null ? new byte[0] : Encoding.UTF8.GetBytes(json.Serialize(body));
            HttpWebRequest request = CreateRequest(method, path, authenticated);
            if (bytes.Length > 0)
            {
                request.ContentType = "application/json; charset=utf-8";
                request.ContentLength = bytes.Length;
                using (Stream output = request.GetRequestStream()) output.Write(bytes, 0, bytes.Length);
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
            {
                string text = reader.ReadToEnd();
                if (typeof(T) == typeof(object) && String.IsNullOrWhiteSpace(text)) return default(T);
                return json.Deserialize<T>(text);
            }
        }

        private byte[] SendBytes(string method, string path, bool authenticated)
        {
            HttpWebRequest request = CreateRequest(method, path, authenticated);
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream input = response.GetResponseStream())
            using (MemoryStream output = new MemoryStream())
            {
                input.CopyTo(output);
                return output.ToArray();
            }
        }

        private byte[] DownloadUpdatePackage(UpdateManifestResponse manifest)
        {
            HttpWebRequest request = CreateRequest("GET", manifest.DownloadPath, true);
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream input = response.GetResponseStream())
            using (MemoryStream output = new MemoryStream())
            {
                long total = response.ContentLength > 0 ? response.ContentLength : manifest.Size;
                long copied = 0;
                int lastReportedPercent = -10;
                DateTime lastReportedAt = DateTime.MinValue;
                byte[] buffer = new byte[128 * 1024];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    copied += read;
                    int percent = total <= 0 ? 0 : (int)Math.Min(99, copied * 100L / total);
                    if (percent >= lastReportedPercent + 5 || DateTime.UtcNow - lastReportedAt >= TimeSpan.FromSeconds(2))
                    {
                        updateStatus = "Скачивается обновление " + manifest.Version + ": " + percent + "%";
                        TrySendHeartbeat();
                        lastReportedPercent = percent;
                        lastReportedAt = DateTime.UtcNow;
                    }
                }
                updateStatus = "Скачивается обновление " + manifest.Version + ": 100%";
                TrySendHeartbeat();
                return output.ToArray();
            }
        }

        private void ReportUpdateStatus(string status)
        {
            updateStatus = status;
            TrySendHeartbeat();
        }

        private void TrySendHeartbeat()
        {
            try { SendHeartbeat(); }
            catch (Exception error) { Log("Не удалось передать промежуточный статус обновления: " + HumanError(error)); }
        }

        private HttpWebRequest CreateRequest(string method, string path, bool authenticated)
        {
            Uri baseUri = new Uri(config.ServerUrl.EndsWith("/") ? config.ServerUrl : config.ServerUrl + "/");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(new Uri(baseUri, path.TrimStart('/')));
            request.Method = method;
            request.Timeout = 20000;
            request.ReadWriteTimeout = 60000;
            request.KeepAlive = false;
            if (authenticated)
            {
                request.Headers["X-DistControl-Client"] = config.ClientId;
                request.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
            }
            return request;
        }

        private AgentConfig LoadConfig()
        {
            if (!File.Exists(configPath))
            {
                AgentConfig created = new AgentConfig();
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                created.TargetUser = Environment.MachineName + "\\" + Environment.UserName;
                created.InstallDirectory = Path.GetDirectoryName(configPath);
                created.PolicyPath = Path.Combine(local, "DistControl", "allow.json");
                created.LogsDirectory = Path.Combine(local, "DistControl", "logs");
                created.NetworkStatePath = Path.Combine(local, "DistControl", "state", "network-state.json");
                config = created;
                SaveConfig();
                return created;
            }
            AgentConfig loaded = json.Deserialize<AgentConfig>(File.ReadAllText(configPath, Encoding.UTF8));
            if (loaded == null) throw new InvalidDataException("Не удалось прочитать agent.json.");
            return loaded;
        }

        private void SaveConfig()
        {
            AtomicWrite(configPath, Encoding.UTF8.GetBytes(json.Serialize(config)));
        }

        private void ValidatePolicy(string policy)
        {
            object parsed = json.DeserializeObject(policy);
            Dictionary<string, object> map = parsed as Dictionary<string, object>;
            if (map == null || !map.ContainsKey("userAssignments") || !map.ContainsKey("vpnProfiles"))
                throw new InvalidDataException("Сервер вернул некорректный allow.json.");
        }

        private void ReadUpdateResult()
        {
            string path = Path.Combine(Path.GetDirectoryName(configPath), "update-result.json");
            if (!File.Exists(path)) return;
            try
            {
                Dictionary<string, object> result = json.DeserializeObject(File.ReadAllText(path, Encoding.UTF8)) as Dictionary<string, object>;
                if (result != null && result.ContainsKey("message")) updateStatus = Convert.ToString(result["message"]);
                File.Delete(path);
            }
            catch { }
        }

        private string AppVersion()
        {
            string path = Path.Combine(config.InstallDirectory ?? "", "DistControl.exe");
            return File.Exists(path) ? FileVersionInfo.GetVersionInfo(path).FileVersion : "";
        }

        private static string AgentVersion()
        {
            return FileVersionInfo.GetVersionInfo(Process.GetCurrentProcess().MainModule.FileName).FileVersion;
        }

        private static string ReadText(string path)
        {
            try { return !String.IsNullOrWhiteSpace(path) && File.Exists(path) ? File.ReadAllText(path, Encoding.UTF8) : ""; }
            catch { return ""; }
        }

        private static void AtomicWrite(string path, byte[] bytes)
        {
            if (String.IsNullOrWhiteSpace(path)) throw new InvalidOperationException("Путь файла не настроен.");
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            string temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllBytes(temp, bytes);
            if (File.Exists(path)) File.Replace(temp, path, path + ".central-backup", true);
            else File.Move(temp, path);
        }

        private static string Protect(string value)
        {
            if (String.IsNullOrEmpty(value)) return "";
            return Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.LocalMachine));
        }

        private static string Unprotect(string value)
        {
            if (String.IsNullOrEmpty(value)) return "";
            try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(value), null, DataProtectionScope.LocalMachine)); }
            catch { return ""; }
        }

        private static string Sha256(string value) { return Sha256(Encoding.UTF8.GetBytes(value ?? "")); }
        private static string Sha256(byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
        }
        private static string Revision(string text) { return String.IsNullOrWhiteSpace(text) ? "" : Sha256(text).Substring(0, 24).ToLowerInvariant(); }
        private static string RandomToken(int byteCount)
        {
            byte[] bytes = new byte[byteCount];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
        private static string SafeName(string value)
        {
            StringBuilder result = new StringBuilder();
            foreach (char character in value ?? "") result.Append(Char.IsLetterOrDigit(character) || ".-_".IndexOf(character) >= 0 ? character : '_');
            return result.Length == 0 ? "update" : result.ToString();
        }

        private string HumanError(Exception error)
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
            return "Ошибка фоновой синхронизации: " + error.Message;
        }

        private void Log(string message)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(logPath));
                if (File.Exists(logPath) && new FileInfo(logPath).Length >= 5L * 1024L * 1024L)
                {
                    string oldest = logPath + ".3";
                    if (File.Exists(oldest)) File.Delete(oldest);
                    for (int index = 2; index >= 1; --index)
                    {
                        string source = logPath + "." + index;
                        if (File.Exists(source)) File.Move(source, logPath + "." + (index + 1));
                    }
                    File.Move(logPath, logPath + ".1");
                }
                File.AppendAllText(logPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + message + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }
    }

    internal sealed class AgentService : ServiceBase
    {
        private readonly string configPath;
        private Thread workerThread;
        private ManualResetEvent stopEvent;

        public AgentService(string configPath)
        {
            ServiceName = "DistControlAgent";
            CanStop = true;
            AutoLog = true;
            this.configPath = configPath;
        }

        protected override void OnStart(string[] args)
        {
            stopEvent = new ManualResetEvent(false);
            workerThread = new Thread(Loop) { IsBackground = true, Name = "DistControl central agent" };
            workerThread.Start();
        }

        protected override void OnStop()
        {
            if (stopEvent != null) stopEvent.Set();
            if (workerThread != null && workerThread.IsAlive) workerThread.Join(10000);
        }

        private void Loop()
        {
            AgentWorker worker = new AgentWorker(configPath);
            try { worker.Initialize(); }
            catch { }
            while (!stopEvent.WaitOne(0))
            {
                worker.RunOnce();
                if (stopEvent.WaitOne(worker.PollSeconds * 1000)) break;
            }
        }

        public void RunConsole(bool once)
        {
            AgentWorker worker = new AgentWorker(configPath);
            worker.Initialize();
            do
            {
                worker.RunOnce();
                if (once) break;
                Thread.Sleep(worker.PollSeconds * 1000);
            } while (true);
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            string config = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "agent.json");
            bool console = Environment.UserInteractive;
            bool once = false;
            for (int i = 0; i < args.Length; ++i)
            {
                if (args[i] == "--service") console = false;
                else if (args[i] == "--console") console = true;
                else if (args[i] == "--once") { console = true; once = true; }
                else if (args[i] == "--config" && i + 1 < args.Length) config = args[++i];
            }
            try
            {
                AgentService service = new AgentService(config);
                if (console) service.RunConsole(once);
                else ServiceBase.Run(service);
                return 0;
            }
            catch (Exception error)
            {
                try { File.AppendAllText(Path.Combine(Path.GetDirectoryName(config), "agent.log"), DateTime.Now.ToString("s") + " " + error + Environment.NewLine); }
                catch { }
                if (console) Console.Error.WriteLine(error.ToString());
                return 1;
            }
        }
    }
}
