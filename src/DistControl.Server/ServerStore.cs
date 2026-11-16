using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace DistControl.Server
{
    public sealed class ServerStore
    {
        private readonly object sync = new object();
        private readonly string dataPath;
        private readonly string packagesDirectory;
        private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
        private ServerData data;

        public ServerStore(string dataDirectory)
        {
            Directory.CreateDirectory(dataDirectory);
            packagesDirectory = Path.Combine(dataDirectory, "packages");
            Directory.CreateDirectory(packagesDirectory);
            dataPath = Path.Combine(dataDirectory, "server-data.json");
            data = LoadOrCreate();
        }

        public EnrollResponse Enroll(EnrollRequest request, string remoteAddress)
        {
            lock (sync)
            {
                if (String.IsNullOrWhiteSpace(request.RequestToken))
                    throw new InvalidDataException("Клиент не передал секрет заявки на регистрацию.");
                if (String.IsNullOrWhiteSpace(request.MachineName))
                    throw new InvalidDataException("Клиент не передал имя компьютера.");

                string requestTokenHash = Hash(request.RequestToken);
                PendingEnrollmentRecord pending = data.PendingEnrollments.FirstOrDefault(delegate(PendingEnrollmentRecord item)
                {
                    return FixedEquals(item.RequestTokenHash, requestTokenHash);
                });
                if (pending == null)
                {
                    pending = new PendingEnrollmentRecord
                    {
                        Id = Guid.NewGuid().ToString("N"),
                        RequestTokenHash = requestTokenHash,
                        MachineName = request.MachineName ?? "",
                        UserName = request.UserName ?? "",
                        AppVersion = request.AppVersion ?? "",
                        AgentVersion = request.AgentVersion ?? "",
                        PolicyJson = String.IsNullOrWhiteSpace(request.PolicyJson) ? EmptyPolicy() : request.PolicyJson,
                        RequestedUtc = UtcNow(),
                        LastRequestUtc = UtcNow(),
                        LastIpAddress = remoteAddress ?? ""
                    };
                    data.PendingEnrollments.Add(pending);
                    AddAudit("SYSTEM", "ENROLLMENT_REQUESTED", pending.Id,
                        pending.MachineName + " / " + pending.UserName + " / " + pending.LastIpAddress);
                    SaveLocked();
                }
                else
                {
                    pending.MachineName = request.MachineName ?? pending.MachineName;
                    pending.UserName = request.UserName ?? pending.UserName;
                    pending.AppVersion = request.AppVersion ?? pending.AppVersion;
                    pending.AgentVersion = request.AgentVersion ?? pending.AgentVersion;
                    pending.LastRequestUtc = UtcNow();
                    pending.LastIpAddress = remoteAddress ?? pending.LastIpAddress;
                }

                if (pending.Rejected)
                {
                    SaveLocked();
                    return new EnrollResponse
                    {
                        Rejected = true,
                        RequestId = pending.Id,
                        Status = "Заявка отклонена администратором домена."
                    };
                }
                if (!pending.Approved)
                {
                    SaveLocked();
                    return new EnrollResponse
                    {
                        RequestId = pending.Id,
                        Status = "Заявка ожидает подтверждения администратором домена."
                    };
                }

                ClientRecord existing = data.Clients.FirstOrDefault(delegate(ClientRecord c)
                {
                    return String.Equals(c.MachineName, request.MachineName, StringComparison.OrdinalIgnoreCase) &&
                        String.Equals(c.UserName, request.UserName, StringComparison.OrdinalIgnoreCase);
                });

                string token = RandomToken(32);
                if (existing == null)
                {
                    existing = new ClientRecord();
                    existing.Id = Guid.NewGuid().ToString("N");
                    existing.MachineName = request.MachineName ?? "";
                    existing.UserName = request.UserName ?? "";
                    existing.PolicyJson = String.IsNullOrWhiteSpace(request.PolicyJson) ? EmptyPolicy() : request.PolicyJson;
                    existing.PolicyRevision = PolicyRevision(existing.PolicyJson);
                    data.Clients.Add(existing);
                }

                existing.TokenHash = Hash(token);
                existing.AppVersion = request.AppVersion ?? "";
                existing.AgentVersion = request.AgentVersion ?? "";
                existing.LastSeenUtc = UtcNow();
                data.PendingEnrollments.Remove(pending);
                AddAudit(pending.DecidedBy, "CLIENT_ENROLLED", existing.Id,
                    existing.MachineName + " / " + existing.UserName);
                SaveLocked();

                return new EnrollResponse
                {
                    Approved = true,
                    RequestId = pending.Id,
                    Status = "Компьютер разрешён администратором домена.",
                    ClientId = existing.Id,
                    ClientToken = token,
                    PolicyRevision = existing.PolicyRevision
                };
            }
        }

        public List<PendingEnrollmentSummary> ListPendingEnrollments()
        {
            lock (sync)
            {
                return data.PendingEnrollments.Select(delegate(PendingEnrollmentRecord item)
                {
                    return new PendingEnrollmentSummary
                    {
                        Id = item.Id,
                        MachineName = item.MachineName,
                        UserName = item.UserName,
                        AppVersion = item.AppVersion,
                        AgentVersion = item.AgentVersion,
                        RequestedUtc = item.RequestedUtc,
                        LastRequestUtc = item.LastRequestUtc,
                        LastIpAddress = item.LastIpAddress,
                        Status = item.Rejected ? "Отклонена" : item.Approved ? "Разрешена, ожидается клиент" : "Ожидает решения",
                        DecidedBy = item.DecidedBy,
                        DecidedUtc = item.DecidedUtc
                    };
                }).OrderByDescending(delegate(PendingEnrollmentSummary item) { return item.RequestedUtc; }).ToList();
            }
        }

        public void DecideEnrollment(string requestId, bool approve, string actor)
        {
            lock (sync)
            {
                PendingEnrollmentRecord pending = data.PendingEnrollments.FirstOrDefault(delegate(PendingEnrollmentRecord item)
                {
                    return String.Equals(item.Id, requestId, StringComparison.OrdinalIgnoreCase);
                });
                if (pending == null) throw new KeyNotFoundException("Заявка на регистрацию не найдена.");
                pending.Approved = approve;
                pending.Rejected = !approve;
                pending.DecidedBy = actor ?? "";
                pending.DecidedUtc = UtcNow();
                AddAudit(actor, approve ? "ENROLLMENT_APPROVED" : "ENROLLMENT_REJECTED", pending.Id,
                    pending.MachineName + " / " + pending.UserName);
                SaveLocked();
            }
        }

        public ClientRecord AuthenticateClient(string clientId, string token)
        {
            lock (sync)
            {
                ClientRecord client = FindClientLocked(clientId);
                if (client == null || !FixedEquals(client.TokenHash, Hash(token ?? "")))
                    throw new UnauthorizedAccessException("Клиент не авторизован.");
                return client;
            }
        }

        public void Heartbeat(string clientId, string token, HeartbeatRequest request, string remoteAddress)
        {
            lock (sync)
            {
                ClientRecord client = RequireClientLocked(clientId, token);
                client.MachineName = request.MachineName ?? client.MachineName;
                client.UserName = request.UserName ?? client.UserName;
                client.AppVersion = request.AppVersion ?? "";
                client.AgentVersion = request.AgentVersion ?? "";
                client.AppliedPolicyRevision = request.AppliedPolicyRevision ?? "";
                client.UpdateStatus = request.UpdateStatus ?? "";
                client.LastError = request.LastError ?? "";
                client.LastNetworkStateJson = request.NetworkStateJson ?? "";
                client.CurrentManualHubs = request.CurrentManualHubs ?? "";
                client.AppliedHubRevision = request.AppliedHubRevision ?? "";
                client.HubStatus = request.HubStatus ?? "";
                client.LastIpAddress = remoteAddress ?? "";
                client.LastSeenUtc = UtcNow();
                SaveLocked();
            }
        }

        public PolicyResponse GetPolicy(string clientId, string token)
        {
            lock (sync)
            {
                ClientRecord client = RequireClientLocked(clientId, token);
                return new PolicyResponse { Revision = client.PolicyRevision, PolicyJson = client.PolicyJson };
            }
        }

        public PolicyResponse GetPolicyForAdmin(string clientId)
        {
            lock (sync)
            {
                ClientRecord client = FindClientLocked(clientId);
                if (client == null) throw new KeyNotFoundException("Компьютер не найден.");
                return new PolicyResponse { Revision = client.PolicyRevision, PolicyJson = client.PolicyJson };
            }
        }

        public PolicyResponse UpdatePolicy(string clientId, PolicyUpdateRequest request)
        {
            lock (sync)
            {
                ClientRecord client = FindClientLocked(clientId);
                if (client == null) throw new KeyNotFoundException("Компьютер не найден.");
                if (!String.IsNullOrEmpty(request.ExpectedRevision) &&
                    !String.Equals(request.ExpectedRevision, client.PolicyRevision, StringComparison.Ordinal))
                    throw new InvalidOperationException("Политика уже изменена другим администратором. Обновите данные.");

                ValidatePolicyJson(request.PolicyJson);
                int oldAccessCount = PolicyAccessCount(client.PolicyJson);
                int newAccessCount = PolicyAccessCount(request.PolicyJson);
                int addedAccessCount = Math.Max(0, newAccessCount - oldAccessCount);
                bool massExpansion = addedAccessCount >= 10 &&
                    newAccessCount > Math.Max(oldAccessCount * 2, oldAccessCount + 10);
                if (massExpansion && !request.ConfirmMassExpansion)
                    throw new InvalidOperationException(
                        "Обнаружено массовое расширение доступа: было " + oldAccessCount +
                        ", станет " + newAccessCount + ". Повторите действие в новой версии админки и подтвердите изменение.");
                client.PolicyJson = request.PolicyJson;
                client.PolicyRevision = PolicyRevision(request.PolicyJson);
                AddAudit(request.Actor, "POLICY_UPDATED", client.Id,
                    "revision=" + client.PolicyRevision + "; accessBefore=" + oldAccessCount +
                    "; accessAfter=" + newAccessCount + "; massConfirmed=" + request.ConfirmMassExpansion);
                SaveLocked();
                return new PolicyResponse { Revision = client.PolicyRevision, PolicyJson = client.PolicyJson };
            }
        }

        public int AppendLogs(string clientId, string token, LogUploadRequest request)
        {
            lock (sync)
            {
                RequireClientLocked(clientId, token);
                HashSet<string> known = new HashSet<string>(data.Logs.Select(delegate(CentralLogRecord x) { return x.Id; }));
                int added = 0;
                foreach (LogUploadItem item in request.Items ?? new List<LogUploadItem>())
                {
                    if (String.IsNullOrWhiteSpace(item.Id) || known.Contains(item.Id) || !IsAuditLogFile(item.FileName)) continue;
                    data.Logs.Add(new CentralLogRecord
                    {
                        Id = item.Id,
                        ClientId = clientId,
                        ReceivedUtc = UtcNow(),
                        FileName = item.FileName ?? "",
                        Text = item.Text ?? ""
                    });
                    known.Add(item.Id);
                    added++;
                }
                TrimLogsLocked();
                if (added > 0) SaveLocked();
                return added;
            }
        }

        public List<ClientSummary> ListClients()
        {
            lock (sync)
            {
                DateTime now = DateTime.UtcNow;
                return data.Clients.Select(delegate(ClientRecord c)
                {
                    DateTime seen;
                    bool parsed = DateTime.TryParse(c.LastSeenUtc, null,
                        System.Globalization.DateTimeStyles.RoundtripKind, out seen);
                    return new ClientSummary
                    {
                        Id = c.Id,
                        MachineName = c.MachineName,
                        UserName = c.UserName,
                        AppVersion = c.AppVersion,
                        AgentVersion = c.AgentVersion,
                        LastSeenUtc = c.LastSeenUtc,
                        LastIpAddress = c.LastIpAddress,
                        PolicyRevision = c.PolicyRevision,
                        AppliedPolicyRevision = c.AppliedPolicyRevision,
                        DesiredVersion = c.DesiredVersion,
                        UpdateStatus = c.UpdateStatus,
                        LastError = c.LastError,
                        AppliedHubRevision = c.AppliedHubRevision,
                        HubStatus = c.HubStatus,
                        CommandStatus = LatestCommandLocked(c.Id) == null ? "" : LatestCommandLocked(c.Id).Status,
                        CommandResult = LatestCommandLocked(c.Id) == null ? "" : LatestCommandLocked(c.Id).Result,
                        Online = parsed && now.Subtract(seen.ToUniversalTime()).TotalSeconds <= 90
                    };
                }).OrderBy(delegate(ClientSummary c) { return c.MachineName; }).ToList();
            }
        }

        public List<CentralLogRecord> ListLogs(string clientId, int limit)
        {
            lock (sync)
            {
                int take = Math.Max(1, Math.Min(limit, 5000));
                return data.Logs.Where(delegate(CentralLogRecord x)
                {
                    return String.IsNullOrWhiteSpace(clientId) || String.Equals(x.ClientId, clientId, StringComparison.OrdinalIgnoreCase);
                }).Reverse().Take(take).Reverse().ToList();
            }
        }

        public List<AuditRecord> ListAudit(int limit)
        {
            lock (sync)
            {
                return data.Audit.AsEnumerable().Reverse().Take(Math.Max(1, Math.Min(limit, 5000))).Reverse().ToList();
            }
        }

        public UpdateRecord PublishUpdate(string version, byte[] package, string expectedSha256, string actor)
        {
            if (String.IsNullOrWhiteSpace(version)) throw new InvalidOperationException("Версия обновления не указана.");
            if (package == null || package.Length == 0) throw new InvalidOperationException("Пакет обновления пуст.");
            string sha = HashBytes(package);
            if (!String.IsNullOrWhiteSpace(expectedSha256) &&
                !String.Equals(expectedSha256.Trim(), sha, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("SHA-256 пакета не совпадает.");

            lock (sync)
            {
                string safeVersion = SafeName(version);
                string fileName = "DistControl-Update-" + safeVersion + ".zip";
                string path = Path.Combine(packagesDirectory, fileName);
                AtomicWrite(path, package);
                UpdateRecord record = data.Updates.FirstOrDefault(delegate(UpdateRecord x)
                {
                    return String.Equals(x.Version, version, StringComparison.OrdinalIgnoreCase);
                });
                if (record == null)
                {
                    record = new UpdateRecord();
                    data.Updates.Add(record);
                }
                record.Version = version;
                record.FileName = fileName;
                record.Sha256 = sha;
                record.Size = package.LongLength;
                record.PublishedUtc = UtcNow();
                record.PublishedBy = actor ?? "";
                AddAudit(actor, "UPDATE_PUBLISHED", version, sha);
                SaveLocked();
                return record;
            }
        }

        public void AssignUpdate(string clientId, UpdateAssignmentRequest request)
        {
            lock (sync)
            {
                ClientRecord client = FindClientLocked(clientId);
                if (client == null) throw new KeyNotFoundException("Компьютер не найден.");
                if (!String.IsNullOrWhiteSpace(request.Version) &&
                    !data.Updates.Any(delegate(UpdateRecord x) { return String.Equals(x.Version, request.Version, StringComparison.OrdinalIgnoreCase); }))
                    throw new KeyNotFoundException("Такая версия обновления не опубликована.");
                client.DesiredVersion = request.Version ?? "";
                client.UpdateStatus = String.IsNullOrWhiteSpace(client.DesiredVersion) ? "" : "Ожидает получения клиентом";
                AddAudit(request.Actor, "UPDATE_ASSIGNED", client.Id, client.DesiredVersion);
                SaveLocked();
            }
        }

        public ClientCommandRecord QueueForceDisconnect(string clientId, string actor)
        {
            lock (sync)
            {
                ClientRecord client = FindClientLocked(clientId);
                if (client == null) throw new KeyNotFoundException("Компьютер не найден.");
                ClientCommandRecord active = data.Commands.LastOrDefault(delegate(ClientCommandRecord item)
                {
                    return String.Equals(item.ClientId, clientId, StringComparison.OrdinalIgnoreCase) &&
                        (item.Status == "Ожидает выполнения" || item.Status == "Выполняется");
                });
                if (active != null) throw new InvalidOperationException("На компьютере уже ожидает выполнения команда администратора.");

                ClientCommandRecord command = new ClientCommandRecord
                {
                    Id = Guid.NewGuid().ToString("N"),
                    ClientId = clientId,
                    Type = "FORCE_DISCONNECT",
                    Status = "Ожидает выполнения",
                    RequestedUtc = UtcNow(),
                    RequestedBy = actor ?? ""
                };
                data.Commands.Add(command);
                if (data.Commands.Count > 20000) data.Commands.RemoveRange(0, data.Commands.Count - 20000);
                AddAudit(actor, "FORCE_DISCONNECT_QUEUED", client.Id,
                    client.MachineName + " / " + client.UserName);
                SaveLocked();
                return command;
            }
        }

        public ClientCommandResponse GetPendingCommand(string clientId, string token)
        {
            lock (sync)
            {
                RequireClientLocked(clientId, token);
                ClientCommandRecord command = data.Commands.FirstOrDefault(delegate(ClientCommandRecord item)
                {
                    return String.Equals(item.ClientId, clientId, StringComparison.OrdinalIgnoreCase) &&
                        (item.Status == "Ожидает выполнения" || item.Status == "Выполняется");
                });
                if (command == null) return new ClientCommandResponse();
                command.Status = "Выполняется";
                SaveLocked();
                return new ClientCommandResponse { Available = true, Id = command.Id, Type = command.Type };
            }
        }

        public void CompleteCommand(string clientId, string token, string commandId, ClientCommandResultRequest request)
        {
            lock (sync)
            {
                RequireClientLocked(clientId, token);
                ClientCommandRecord command = data.Commands.FirstOrDefault(delegate(ClientCommandRecord item)
                {
                    return String.Equals(item.Id, commandId, StringComparison.OrdinalIgnoreCase) &&
                        String.Equals(item.ClientId, clientId, StringComparison.OrdinalIgnoreCase);
                });
                if (command == null) throw new KeyNotFoundException("Команда для компьютера не найдена.");
                if (command.Status == "Выполнено" || command.Status == "Ошибка") return;
                command.Status = request != null && request.Success ? "Выполнено" : "Ошибка";
                command.Result = request == null ? "Клиент не передал результат команды." : (request.Message ?? "");
                command.CompletedUtc = UtcNow();
                AddAudit("CLIENT", request != null && request.Success
                    ? "FORCE_DISCONNECT_COMPLETED" : "FORCE_DISCONNECT_FAILED", clientId, command.Result);
                SaveLocked();
            }
        }

        public UpdateManifestResponse GetUpdate(string clientId, string token)
        {
            lock (sync)
            {
                ClientRecord client = RequireClientLocked(clientId, token);
                UpdateRecord update = data.Updates.FirstOrDefault(delegate(UpdateRecord x)
                {
                    return String.Equals(x.Version, client.DesiredVersion, StringComparison.OrdinalIgnoreCase);
                });
                if (update == null || VersionsEquivalent(client.AppVersion, update.Version))
                    return new UpdateManifestResponse();
                return new UpdateManifestResponse
                {
                    Available = true,
                    Version = update.Version,
                    Sha256 = update.Sha256,
                    Size = update.Size,
                    DownloadPath = "/api/v1/client/update/package"
                };
            }
        }

        public HubConfiguration GetHubConfiguration()
        {
            lock (sync)
            {
                return new HubConfiguration
                {
                    Revision = data.Hubs.Revision,
                    ManualHubs = data.Hubs.ManualHubs,
                    DiscoveredManualHubs = DiscoveredManualHubsLocked(),
                    UpdatedUtc = data.Hubs.UpdatedUtc,
                    UpdatedBy = data.Hubs.UpdatedBy
                };
            }
        }

        public HubConfiguration UpdateHubConfiguration(HubConfigurationUpdateRequest request, string actor)
        {
            lock (sync)
            {
                string normalized = NormalizeManualHubs(request == null ? "" : request.ManualHubs);
                data.Hubs.ManualHubs = normalized;
                data.Hubs.Revision = PolicyRevision(normalized);
                data.Hubs.UpdatedUtc = UtcNow();
                data.Hubs.UpdatedBy = actor ?? "";
                AddAudit(actor, "HUBS_UPDATED", "GLOBAL", normalized);
                SaveLocked();
                return GetHubConfiguration();
            }
        }

        public byte[] GetUpdatePackage(string clientId, string token, out UpdateRecord update)
        {
            lock (sync)
            {
                ClientRecord client = RequireClientLocked(clientId, token);
                update = data.Updates.FirstOrDefault(delegate(UpdateRecord x)
                {
                    return String.Equals(x.Version, client.DesiredVersion, StringComparison.OrdinalIgnoreCase);
                });
                if (update == null) throw new KeyNotFoundException("Обновление клиенту не назначено.");
                return File.ReadAllBytes(Path.Combine(packagesDirectory, update.FileName));
            }
        }

        private ServerData LoadOrCreate()
        {
            if (File.Exists(dataPath))
            {
                string text = File.ReadAllText(dataPath, Encoding.UTF8);
                ServerData loaded = json.Deserialize<ServerData>(text);
                if (loaded == null) throw new InvalidDataException("Не удалось прочитать серверное хранилище.");
                Normalize(loaded);
                loaded.SchemaVersion = 4;
                AtomicWrite(dataPath, Encoding.UTF8.GetBytes(json.Serialize(loaded)));
                WriteBootstrapInformation();
                return loaded;
            }

            ServerData created = new ServerData();
            data = created;
            SaveLocked();
            WriteBootstrapInformation();
            return created;
        }

        private void WriteBootstrapInformation()
        {
            string bootstrap = "Регистрация клиентов: по подтверждению администратора домена" + Environment.NewLine +
                "Административный доступ: встроенная Windows-аутентификация, группа Domain Admins" + Environment.NewLine +
                "Создано: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + Environment.NewLine;
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(dataPath), "bootstrap.txt"), bootstrap, Encoding.UTF8);
        }

        private void Normalize(ServerData value)
        {
            value.SchemaVersion = 4;
            if (value.Clients == null) value.Clients = new List<ClientRecord>();
            if (value.PendingEnrollments == null) value.PendingEnrollments = new List<PendingEnrollmentRecord>();
            if (value.Logs == null) value.Logs = new List<CentralLogRecord>();
            value.Logs.RemoveAll(delegate(CentralLogRecord item) { return !IsAuditLogFile(item.FileName); });
            if (value.Updates == null) value.Updates = new List<UpdateRecord>();
            if (value.Audit == null) value.Audit = new List<AuditRecord>();
            if (value.Commands == null) value.Commands = new List<ClientCommandRecord>();
            if (value.Hubs == null) value.Hubs = new HubConfiguration();
        }

        private ClientRecord FindClientLocked(string id)
        {
            return data.Clients.FirstOrDefault(delegate(ClientRecord c) { return String.Equals(c.Id, id, StringComparison.OrdinalIgnoreCase); });
        }

        private ClientCommandRecord LatestCommandLocked(string clientId)
        {
            return data.Commands.LastOrDefault(delegate(ClientCommandRecord item)
            {
                return String.Equals(item.ClientId, clientId, StringComparison.OrdinalIgnoreCase);
            });
        }

        private ClientRecord RequireClientLocked(string id, string token)
        {
            ClientRecord client = FindClientLocked(id);
            if (client == null || !FixedEquals(client.TokenHash, Hash(token ?? "")))
                throw new UnauthorizedAccessException("Клиент не авторизован.");
            return client;
        }

        private void AddAudit(string actor, string action, string target, string details)
        {
            data.Audit.Add(new AuditRecord
            {
                TimestampUtc = UtcNow(),
                Actor = String.IsNullOrWhiteSpace(actor) ? "SYSTEM" : actor,
                Action = action ?? "",
                Target = target ?? "",
                Details = details ?? ""
            });
            if (data.Audit.Count > 20000) data.Audit.RemoveRange(0, data.Audit.Count - 20000);
        }

        private void TrimLogsLocked()
        {
            if (data.Logs.Count > 100000) data.Logs.RemoveRange(0, data.Logs.Count - 100000);
        }

        private static bool IsAuditLogFile(string fileName)
        {
            string name = Path.GetFileName(fileName ?? "");
            return name.StartsWith("audit-", StringComparison.OrdinalIgnoreCase) &&
                String.Equals(Path.GetExtension(name), ".csv", StringComparison.OrdinalIgnoreCase);
        }

        private T Read<T>(Func<T> value)
        {
            lock (sync) { return value(); }
        }

        private void SaveLocked()
        {
            string text = json.Serialize(data);
            AtomicWrite(dataPath, Encoding.UTF8.GetBytes(text));
        }

        private static void AtomicWrite(string path, byte[] bytes)
        {
            string temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllBytes(temp, bytes);
            if (File.Exists(path)) File.Replace(temp, path, path + ".bak", true);
            else File.Move(temp, path);
        }

        private void ValidatePolicyJson(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) throw new InvalidDataException("Политика пуста.");
            object root = json.DeserializeObject(text);
            if (!(root is Dictionary<string, object>)) throw new InvalidDataException("Корень allow.json должен быть объектом.");
            Dictionary<string, object> map = (Dictionary<string, object>)root;
            if (!map.ContainsKey("userAssignments") || !map.ContainsKey("vpnProfiles"))
                throw new InvalidDataException("В allow.json отсутствуют userAssignments или vpnProfiles.");
        }

        private int PolicyAccessCount(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) return 0;
            object parsed = json.DeserializeObject(text);
            Dictionary<string, object> root = parsed as Dictionary<string, object>;
            if (root == null) return 0;
            object assignmentsValue;
            IList assignments = root.TryGetValue("userAssignments", out assignmentsValue)
                ? assignmentsValue as IList : null;
            if (assignments == null) return 0;

            int count = 0;
            foreach (object assignmentValue in assignments)
            {
                Dictionary<string, object> assignment = assignmentValue as Dictionary<string, object>;
                if (assignment == null) continue;
                object rulesValue;
                IList rules = assignment.TryGetValue("allowedDevices", out rulesValue)
                    ? rulesValue as IList : null;
                if (rules != null) count += rules.Count;
            }
            return count;
        }

        public static string PolicyRevision(string value)
        {
            return Hash(value ?? "").Substring(0, 24).ToLowerInvariant();
        }

        public static string Hash(string value)
        {
            return HashBytes(Encoding.UTF8.GetBytes(value ?? ""));
        }

        public static string HashBytes(byte[] value)
        {
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(value)).Replace("-", "");
        }

        private static bool FixedEquals(string left, string right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int difference = 0;
            for (int i = 0; i < left.Length; ++i) difference |= left[i] ^ right[i];
            return difference == 0;
        }

        private static string RandomToken(int byteCount)
        {
            byte[] bytes = new byte[byteCount];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string NormalizeManualHubs(string value)
        {
            List<string> result = new List<string>();
            string[] entries = (value ?? "").Split(new[] { ',', ';', '\r', '\n', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string raw in entries)
            {
                string entry = raw.Trim();
                int separator = entry.LastIndexOf(':');
                string addressText = separator < 0 ? entry : entry.Substring(0, separator);
                string portText = separator < 0 ? "6565" : entry.Substring(separator + 1);
                IPAddress address;
                int port;
                if (!IPAddress.TryParse(addressText, out address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    throw new InvalidDataException("Некорректный IPv4-адрес USB-сервера: " + entry + ".");
                if (!Int32.TryParse(portText, out port) || port < 1 || port > 65535)
                    throw new InvalidDataException("Некорректный порт USB-сервера: " + entry + ".");
                string normalized = address + ":" + port;
                if (!result.Contains(normalized, StringComparer.OrdinalIgnoreCase)) result.Add(normalized);
            }
            return String.Join(",", result.ToArray());
        }

        private string DiscoveredManualHubsLocked()
        {
            List<string> discovered = new List<string>();
            foreach (ClientRecord client in data.Clients)
            {
                string normalized;
                try { normalized = NormalizeManualHubs(client.CurrentManualHubs); }
                catch { continue; }
                foreach (string endpoint in normalized.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    if (!discovered.Contains(endpoint, StringComparer.OrdinalIgnoreCase)) discovered.Add(endpoint);
            }
            return String.Join(",", discovered.ToArray());
        }

        private static string RandomDigits(int count)
        {
            byte[] bytes = new byte[count];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
            StringBuilder result = new StringBuilder(count);
            foreach (byte value in bytes) result.Append((char)('0' + (value % 10)));
            return result.ToString();
        }

        private static string SafeName(string value)
        {
            StringBuilder result = new StringBuilder();
            foreach (char character in value)
                result.Append(Char.IsLetterOrDigit(character) || character == '.' || character == '-' || character == '_' ? character : '_');
            return result.Length == 0 ? "update" : result.ToString();
        }

        private static string UtcNow()
        {
            return DateTime.UtcNow.ToString("o");
        }

        private static bool VersionsEquivalent(string left, string right)
        {
            if (String.Equals(left, right, StringComparison.OrdinalIgnoreCase)) return true;
            Version leftVersion;
            Version rightVersion;
            if (!Version.TryParse(left, out leftVersion) || !Version.TryParse(right, out rightVersion)) return false;
            return Component(leftVersion.Major) == Component(rightVersion.Major) &&
                Component(leftVersion.Minor) == Component(rightVersion.Minor) &&
                Component(leftVersion.Build) == Component(rightVersion.Build) &&
                Component(leftVersion.Revision) == Component(rightVersion.Revision);
        }

        private static int Component(int value)
        {
            return value < 0 ? 0 : value;
        }

        private static string EmptyPolicy()
        {
            return "{\n  \"pipeName\": \"dkclient\",\n  \"refreshSeconds\": 5,\n  \"vpnProfiles\": [],\n  \"userAssignments\": []\n}\n";
        }
    }
}
