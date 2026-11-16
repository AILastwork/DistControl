using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

[assembly: AssemblyTitle("DistControl Updater")]
[assembly: AssemblyProduct("DistControl")]
[assembly: AssemblyVersion("0.8.0.0")]
[assembly: AssemblyFileVersion("0.8.0.0")]

namespace DistControl.Updater
{
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

    internal static class Program
    {
        private static int Main(string[] args)
        {
            Dictionary<string, string> options = Parse(args);
            string staging = Value(options, "--staging");
            string install = Value(options, "--install");
            string serviceName = Value(options, "--service");
            string resultPath = Value(options, "--result");
            int waitPid;
            Int32.TryParse(Value(options, "--wait-pid"), out waitPid);

            try
            {
                if (waitPid > 0)
                {
                    try { Process.GetProcessById(waitPid).WaitForExit(60000); } catch (ArgumentException) { }
                }
                StopService(serviceName);
                Apply(staging, install);
                WriteResult(resultPath, true, "Обновление установлено успешно");
                StartService(serviceName);
                return 0;
            }
            catch (Exception error)
            {
                WriteResult(resultPath, false, "Обновление не установлено: " + error.Message);
                try { StartService(serviceName); } catch { }
                return 1;
            }
        }

        private static void Apply(string staging, string install)
        {
            if (!Directory.Exists(staging)) throw new DirectoryNotFoundException("Папка обновления не найдена.");
            Directory.CreateDirectory(install);
            JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
            UpdatePackageManifest manifest = json.Deserialize<UpdatePackageManifest>(
                File.ReadAllText(Path.Combine(staging, "manifest.json"), Encoding.UTF8));
            if (manifest == null || manifest.Files == null || manifest.Files.Count == 0)
                throw new InvalidDataException("Манифест обновления пуст.");

            string backup = Path.Combine(Path.GetDirectoryName(staging), "backup-" + DateTime.Now.ToString("yyyyMMddHHmmss"));
            Directory.CreateDirectory(backup);
            List<string> copied = new List<string>();
            try
            {
                foreach (UpdatePackageFile item in manifest.Files)
                {
                    string relative = item.Path.Replace('/', Path.DirectorySeparatorChar);
                    string source = SafePath(staging, relative);
                    string target = SafePath(install, relative);
                    string targetDirectory = Path.GetDirectoryName(target);
                    Directory.CreateDirectory(targetDirectory);
                    if (File.Exists(target))
                    {
                        string backupFile = SafePath(backup, relative);
                        Directory.CreateDirectory(Path.GetDirectoryName(backupFile));
                        File.Copy(target, backupFile, true);
                    }
                    File.Copy(source, target, true);
                    copied.Add(relative);
                }
            }
            catch
            {
                foreach (string relative in copied.AsEnumerable().Reverse())
                {
                    string backupFile = SafePath(backup, relative);
                    string target = SafePath(install, relative);
                    if (File.Exists(backupFile)) File.Copy(backupFile, target, true);
                    else if (File.Exists(target)) File.Delete(target);
                }
                throw;
            }
        }

        private static string SafePath(string root, string relative)
        {
            string normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string full = Path.GetFullPath(Path.Combine(normalizedRoot, relative));
            if (!full.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Недопустимый путь обновления: " + relative);
            return full;
        }

        private static void StopService(string name)
        {
            if (String.IsNullOrWhiteSpace(name)) return;
            using (ServiceController service = new ServiceController(name))
            {
                try
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.StopPending)
                        service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                }
                catch (InvalidOperationException) { }
            }
        }

        private static void StartService(string name)
        {
            if (String.IsNullOrWhiteSpace(name)) return;
            try
            {
                using (ServiceController service = new ServiceController(name))
                {
                    service.Refresh();
                    if (service.Status == ServiceControllerStatus.Stopped)
                    {
                        service.Start();
                        service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
                    }
                }
            }
            catch (InvalidOperationException) { }
        }

        private static void WriteResult(string path, bool success, string message)
        {
            if (String.IsNullOrWhiteSpace(path)) return;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                JavaScriptSerializer json = new JavaScriptSerializer();
                File.WriteAllText(path, json.Serialize(new { success = success, message = message, utc = DateTime.UtcNow.ToString("o") }), Encoding.UTF8);
            }
            catch { }
        }

        private static Dictionary<string, string> Parse(string[] args)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; ++i)
                if (args[i].StartsWith("--") && i + 1 < args.Length) result[args[i]] = args[++i];
            return result;
        }

        private static string Value(Dictionary<string, string> values, string name)
        {
            string value;
            return values.TryGetValue(name, out value) ? value : "";
        }
    }
}
