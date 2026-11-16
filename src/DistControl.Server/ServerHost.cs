using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DistControl.Server
{
    internal sealed class RequestData
    {
        public string Method = "";
        public string Path = "";
        public Dictionary<string, string> Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public byte[] Body = new byte[0];
        public string RemoteAddress = "";
        public WindowsIdentity WindowsIdentity;
        public string AuthenticatedUser = "";

        public string Header(string name)
        {
            string value;
            return Headers.TryGetValue(name, out value) ? value : "";
        }
    }

    public sealed class ServerHost : IDisposable
    {
        private readonly string prefix;
        private readonly ServerStore store;
        private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
        private HttpListener listener;
        private Thread acceptThread;
        private volatile bool stopping;

        public ServerHost(string prefix, string dataDirectory)
        {
            this.prefix = prefix;
            store = new ServerStore(dataDirectory);
        }

        public void Start()
        {
            string listenerPrefix = prefix.EndsWith("/") ? prefix : prefix + "/";
            listener = new HttpListener();
            listener.Prefixes.Add(listenerPrefix);
            listener.IgnoreWriteExceptions = true;
            listener.AuthenticationSchemeSelectorDelegate = delegate(HttpListenerRequest request)
            {
                return request.Url.AbsolutePath.StartsWith("/api/v1/admin", StringComparison.OrdinalIgnoreCase)
                    ? AuthenticationSchemes.Negotiate
                    : AuthenticationSchemes.Anonymous;
            };
            listener.Start();
            acceptThread = new Thread(AcceptLoop) { IsBackground = true, Name = "DistControl server API" };
            acceptThread.Start();
        }

        public void Stop()
        {
            stopping = true;
            try { if (listener != null) listener.Close(); } catch { }
            if (acceptThread != null && acceptThread.IsAlive) acceptThread.Join(5000);
        }

        public void Dispose()
        {
            Stop();
        }

        private void AcceptLoop()
        {
            while (!stopping)
            {
                try
                {
                    HttpListenerContext context = listener.GetContext();
                    ThreadPool.QueueUserWorkItem(delegate { HandleClientConnection(context); });
                }
                catch (HttpListenerException) { if (!stopping) Thread.Sleep(250); }
                catch (ObjectDisposedException) { return; }
                catch { Thread.Sleep(250); }
            }
        }

        private void HandleClientConnection(HttpListenerContext context)
        {
            try
            {
                Handle(context.Response, ReadRequest(context));
            }
            catch (InvalidDataException error) { try { WriteError(context.Response, 400, error.Message); } catch { } }
            catch { try { WriteError(context.Response, 500, "Внутренняя ошибка сервера."); } catch { } }
        }

        private void Handle(HttpListenerResponse response, RequestData request)
        {
            try
            {
                string path = request.Path.TrimEnd('/');
                string method = request.Method.ToUpperInvariant();
                if (path == "") path = "/";

                if (path == "/" && method == "GET")
                {
                    WriteStatusPage(response);
                    return;
                }
                if (path == "/health" && method == "GET")
                {
                    WriteJson(response, 200, new { status = "ok", utc = DateTime.UtcNow.ToString("o") });
                    return;
                }
                if (path == "/api/v1/enroll" && method == "POST")
                {
                    WriteJson(response, 200, store.Enroll(ReadJson<EnrollRequest>(request), request.RemoteAddress));
                    return;
                }

                string[] parts = path.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "client")
                {
                    HandleAgent(response, request, parts, method);
                    return;
                }
                if (parts.Length >= 3 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "admin")
                {
                    RequireAdmin(request);
                    HandleAdmin(response, request, parts, method);
                    return;
                }

                WriteError(response, 404, "Адрес API не найден.");
            }
            catch (UnauthorizedAccessException error) { WriteError(response, 401, error.Message); }
            catch (KeyNotFoundException error) { WriteError(response, 404, error.Message); }
            catch (InvalidOperationException error) { WriteError(response, 409, error.Message); }
            catch (InvalidDataException error) { WriteError(response, 400, error.Message); }
            catch (Exception error) { WriteError(response, 500, "Внутренняя ошибка сервера: " + error.Message); }
        }

        private void HandleAgent(HttpListenerResponse response, RequestData request, string[] parts, string method)
        {
            string clientId = request.Header("X-DistControl-Client");
            string token = BearerToken(request.Header("Authorization"));
            if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(token))
                throw new UnauthorizedAccessException("Не указаны данные клиента.");

            string action = parts[3];
            if (action == "heartbeat" && method == "POST")
            {
                store.Heartbeat(clientId, token, ReadJson<HeartbeatRequest>(request), request.RemoteAddress);
                WriteJson(response, 200, new { accepted = true });
                return;
            }
            if (action == "policy" && method == "GET")
            {
                WriteJson(response, 200, store.GetPolicy(clientId, token));
                return;
            }
            if (action == "hubs" && method == "GET")
            {
                store.AuthenticateClient(clientId, token);
                WriteJson(response, 200, store.GetHubConfiguration());
                return;
            }
            if (action == "logs" && method == "POST")
            {
                int added = store.AppendLogs(clientId, token, ReadJson<LogUploadRequest>(request));
                WriteJson(response, 200, new { accepted = added });
                return;
            }
            if (action == "command" && parts.Length == 4 && method == "GET")
            {
                WriteJson(response, 200, store.GetPendingCommand(clientId, token));
                return;
            }
            if (action == "command" && parts.Length == 6 && parts[5] == "result" && method == "POST")
            {
                store.CompleteCommand(clientId, token, parts[4], ReadJson<ClientCommandResultRequest>(request));
                WriteJson(response, 200, new { accepted = true });
                return;
            }
            if (action == "update" && parts.Length == 4 && method == "GET")
            {
                WriteJson(response, 200, store.GetUpdate(clientId, token));
                return;
            }
            if (action == "update" && parts.Length == 5 && parts[4] == "package" && method == "GET")
            {
                UpdateRecord update;
                byte[] package = store.GetUpdatePackage(clientId, token, out update);
                Dictionary<string, string> headers = new Dictionary<string, string>();
                headers["X-DistControl-Version"] = update.Version;
                headers["X-DistControl-SHA256"] = update.Sha256;
                WriteResponse(response, 200, "application/zip", package, headers);
                return;
            }
            WriteError(response, 404, "Команда клиента не найдена.");
        }

        private void HandleAdmin(HttpListenerResponse response, RequestData request, string[] parts, string method)
        {
            if (parts.Length == 4 && parts[3] == "clients" && method == "GET")
            {
                WriteJson(response, 200, store.ListClients());
                return;
            }
            if (parts.Length == 4 && parts[3] == "enrollments" && method == "GET")
            {
                WriteJson(response, 200, store.ListPendingEnrollments());
                return;
            }
            if (parts.Length == 4 && parts[3] == "hubs")
            {
                if (method == "GET") WriteJson(response, 200, store.GetHubConfiguration());
                else if (method == "PUT")
                    WriteJson(response, 200, store.UpdateHubConfiguration(
                        ReadJson<HubConfigurationUpdateRequest>(request), request.AuthenticatedUser));
                else WriteError(response, 405, "Метод не поддерживается.");
                return;
            }
            if (parts.Length == 6 && parts[3] == "enrollments" && method == "POST" &&
                (parts[5] == "approve" || parts[5] == "reject"))
            {
                store.DecideEnrollment(parts[4], parts[5] == "approve", request.AuthenticatedUser);
                WriteJson(response, 200, new { accepted = true });
                return;
            }
            if (parts.Length == 6 && parts[3] == "clients" && parts[5] == "policy")
            {
                if (method == "GET") WriteJson(response, 200, store.GetPolicyForAdmin(parts[4]));
                else if (method == "PUT")
                {
                    PolicyUpdateRequest update = ReadJson<PolicyUpdateRequest>(request);
                    update.Actor = request.AuthenticatedUser;
                    WriteJson(response, 200, store.UpdatePolicy(parts[4], update));
                }
                else WriteError(response, 405, "Метод не поддерживается.");
                return;
            }
            if (parts.Length == 6 && parts[3] == "clients" && parts[5] == "update" && method == "POST")
            {
                UpdateAssignmentRequest assignment = ReadJson<UpdateAssignmentRequest>(request);
                assignment.Actor = request.AuthenticatedUser;
                store.AssignUpdate(parts[4], assignment);
                WriteJson(response, 200, new { accepted = true });
                return;
            }
            if (parts.Length == 6 && parts[3] == "clients" && parts[5] == "disconnect" && method == "POST")
            {
                WriteJson(response, 200, store.QueueForceDisconnect(parts[4], request.AuthenticatedUser));
                return;
            }
            if (parts.Length == 4 && parts[3] == "logs" && method == "GET")
            {
                int limit;
                if (!Int32.TryParse(Query(request, "limit"), out limit)) limit = 500;
                WriteJson(response, 200, store.ListLogs(Query(request, "clientId"), limit));
                return;
            }
            if (parts.Length == 4 && parts[3] == "audit" && method == "GET")
            {
                int limit;
                if (!Int32.TryParse(Query(request, "limit"), out limit)) limit = 500;
                WriteJson(response, 200, store.ListAudit(limit));
                return;
            }
            if (parts.Length == 5 && parts[3] == "updates" && method == "POST")
            {
                string version = Uri.UnescapeDataString(parts[4]);
                WriteJson(response, 200, store.PublishUpdate(version, request.Body,
                    request.Header("X-DistControl-SHA256"), request.AuthenticatedUser));
                return;
            }
            WriteError(response, 404, "Команда администратора не найдена.");
        }

        private void RequireAdmin(RequestData request)
        {
            WindowsIdentity identity = request.WindowsIdentity;
            if (identity == null || !identity.IsAuthenticated || identity.User == null || identity.User.AccountDomainSid == null)
                throw new UnauthorizedAccessException("Требуется доменная учётная запись Windows.");
            SecurityIdentifier domainAdmins = new SecurityIdentifier(identity.User.AccountDomainSid.Value + "-512");
            if (!new WindowsPrincipal(identity).IsInRole(domainAdmins))
                throw new UnauthorizedAccessException("Доступ разрешён только участникам группы Domain Admins.");
            request.AuthenticatedUser = identity.Name;
        }

        private T ReadJson<T>(RequestData request)
        {
            T value = json.Deserialize<T>(Encoding.UTF8.GetString(request.Body));
            if (value == null) throw new InvalidDataException("Пустой JSON-запрос.");
            return value;
        }

        private void WriteJson(HttpListenerResponse response, int status, object value)
        {
            WriteResponse(response, status, "application/json; charset=utf-8", Encoding.UTF8.GetBytes(json.Serialize(value)), null);
        }

        private void WriteError(HttpListenerResponse response, int status, string message)
        {
            try { WriteJson(response, status, new { error = message ?? "Неизвестная ошибка." }); } catch { }
        }

        private static void WriteStatusPage(HttpListenerResponse response)
        {
            string html =
                "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">" +
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
                "<title>DistControl Server</title>" +
                "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:48px;color:#202124}" +
                "main{max-width:680px}h1{font-size:28px;margin:0 0 16px}" +
                ".ok{color:#137333;font-weight:600}p{line-height:1.5}" +
                "code{background:#f1f3f4;padding:2px 6px}</style></head><body><main>" +
                "<h1>DistControl Server</h1><p class=\"ok\">Сервер работает.</p>" +
                "<p>Централизованное управление выполняется через приложение DistControl Central Admin.</p>" +
                "<p>Версия API: <code>v1</code>. Проверка состояния: <a href=\"/health\">/health</a>.</p>" +
                "</main></body></html>";
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["Cache-Control"] = "no-store";
            WriteResponse(response, 200, "text/html; charset=utf-8", Encoding.UTF8.GetBytes(html), headers);
        }

        private static RequestData ReadRequest(HttpListenerContext context)
        {
            HttpListenerRequest source = context.Request;
            RequestData request = new RequestData();
            request.Method = source.HttpMethod;
            request.Path = source.Url.AbsolutePath;
            IPEndPoint remote = source.RemoteEndPoint;
            request.RemoteAddress = remote == null ? "" : remote.Address.ToString();
            request.WindowsIdentity = context.User == null ? null : context.User.Identity as WindowsIdentity;
            foreach (string name in source.Headers.AllKeys)
                request.Headers[name] = source.Headers[name] ?? "";
            foreach (string name in source.QueryString.AllKeys)
                if (name != null) request.Query[name] = source.QueryString[name] ?? "";

            const int maximumBody = 256 * 1024 * 1024;
            if (source.ContentLength64 > maximumBody)
                throw new InvalidDataException("Запрос слишком большой.");
            using (MemoryStream body = new MemoryStream())
            {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = source.InputStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    if (body.Length + read > maximumBody) throw new InvalidDataException("Запрос слишком большой.");
                    body.Write(buffer, 0, read);
                }
                request.Body = body.ToArray();
            }
            return request;
        }

        private static RequestData ReadRequest(NetworkStream stream, TcpClient client)
        {
            byte[] headerBytes = ReadHeader(stream, 64 * 1024);
            string[] lines = Encoding.ASCII.GetString(headerBytes).Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0) throw new InvalidDataException("Пустой HTTP-запрос.");
            string[] first = lines[0].Split(' ');
            if (first.Length < 2) throw new InvalidDataException("Некорректная строка HTTP-запроса.");

            RequestData request = new RequestData();
            request.Method = first[0];
            ParseTarget(first[1], request);
            IPEndPoint remote = client.Client.RemoteEndPoint as IPEndPoint;
            request.RemoteAddress = remote == null ? "" : remote.Address.ToString();
            for (int i = 1; i < lines.Length; ++i)
            {
                int colon = lines[i].IndexOf(':');
                if (colon > 0) request.Headers[lines[i].Substring(0, colon).Trim()] = lines[i].Substring(colon + 1).Trim();
            }

            string lengthText = request.Header("Content-Length");
            int length = 0;
            if (!String.IsNullOrWhiteSpace(lengthText) && (!Int32.TryParse(lengthText, out length) || length < 0))
                throw new InvalidDataException("Некорректный Content-Length.");
            if (length > 256 * 1024 * 1024) throw new InvalidDataException("Запрос слишком большой.");
            request.Body = ReadExact(stream, length);
            return request;
        }

        private static byte[] ReadHeader(Stream stream, int maximum)
        {
            using (MemoryStream output = new MemoryStream())
            {
                int state = 0;
                while (output.Length < maximum)
                {
                    int value = stream.ReadByte();
                    if (value < 0) throw new EndOfStreamException();
                    output.WriteByte((byte)value);
                    if ((state == 0 || state == 2) && value == '\r') state++;
                    else if ((state == 1 || state == 3) && value == '\n') state++;
                    else state = value == '\r' ? 1 : 0;
                    if (state == 4)
                    {
                        byte[] bytes = output.ToArray();
                        Array.Resize(ref bytes, bytes.Length - 4);
                        return bytes;
                    }
                }
            }
            throw new InvalidDataException("HTTP-заголовок слишком большой.");
        }

        private static byte[] ReadExact(Stream stream, int length)
        {
            byte[] result = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                int read = stream.Read(result, offset, length - offset);
                if (read <= 0) throw new EndOfStreamException();
                offset += read;
            }
            return result;
        }

        private static void ParseTarget(string target, RequestData request)
        {
            int question = target.IndexOf('?');
            request.Path = Uri.UnescapeDataString(question < 0 ? target : target.Substring(0, question));
            if (question < 0) return;
            foreach (string pair in target.Substring(question + 1).Split('&'))
            {
                if (pair.Length == 0) continue;
                int equals = pair.IndexOf('=');
                string key = equals < 0 ? pair : pair.Substring(0, equals);
                string value = equals < 0 ? "" : pair.Substring(equals + 1);
                request.Query[Uri.UnescapeDataString(key.Replace('+', ' '))] = Uri.UnescapeDataString(value.Replace('+', ' '));
            }
        }

        private static string Query(RequestData request, string name)
        {
            string value;
            return request.Query.TryGetValue(name, out value) ? value : "";
        }

        private static void WriteResponse(HttpListenerResponse response, int status, string contentType, byte[] body, Dictionary<string, string> extraHeaders)
        {
            response.StatusCode = status;
            response.StatusDescription = Reason(status);
            response.ContentType = contentType;
            response.ContentLength64 = body.LongLength;
            response.KeepAlive = false;
            response.Headers["X-Content-Type-Options"] = "nosniff";
            if (extraHeaders != null)
                foreach (KeyValuePair<string, string> item in extraHeaders)
                    response.Headers[item.Key] = item.Value.Replace("\r", "").Replace("\n", "");
            try { response.OutputStream.Write(body, 0, body.Length); }
            finally { response.Close(); }
        }

        private static string Reason(int status)
        {
            switch (status)
            {
                case 200: return "OK";
                case 400: return "Bad Request";
                case 401: return "Unauthorized";
                case 403: return "Forbidden";
                case 404: return "Not Found";
                case 405: return "Method Not Allowed";
                case 409: return "Conflict";
                default: return "Internal Server Error";
            }
        }

        private static string BearerToken(string header)
        {
            const string bearer = "Bearer ";
            return !String.IsNullOrWhiteSpace(header) && header.StartsWith(bearer, StringComparison.OrdinalIgnoreCase)
                ? header.Substring(bearer.Length).Trim() : "";
        }

        private static Uri ParsePrefix(string value)
        {
            string normalized = value.Replace("http://+:", "http://0.0.0.0:").Replace("http://*:", "http://0.0.0.0:");
            Uri result;
            if (!Uri.TryCreate(normalized, UriKind.Absolute, out result) || result.Scheme != Uri.UriSchemeHttp)
                throw new InvalidOperationException("Адрес сервера должен иметь вид http://адрес:порт/.");
            return result;
        }

        private static IPAddress BindAddress(string host)
        {
            if (host == "0.0.0.0" || host == "+" || host == "*") return IPAddress.Any;
            if (String.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)) return IPAddress.Loopback;
            IPAddress parsed;
            if (IPAddress.TryParse(host, out parsed)) return parsed;
            foreach (IPAddress address in Dns.GetHostAddresses(host))
                if (address.AddressFamily == AddressFamily.InterNetwork) return address;
            throw new InvalidOperationException("Не удалось определить адрес сервера: " + host);
        }
    }
}
