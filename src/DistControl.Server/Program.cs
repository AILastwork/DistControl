using System;
using System.IO;
using System.Reflection;
using System.ServiceProcess;
using System.Threading;

[assembly: AssemblyTitle("DistControl Server")]
[assembly: AssemblyProduct("DistControl")]
[assembly: AssemblyVersion("0.8.1.0")]
[assembly: AssemblyFileVersion("0.8.1.0")]

namespace DistControl.Server
{
    internal sealed class DistControlServerService : ServiceBase
    {
        private readonly string prefix;
        private readonly string dataDirectory;
        private ServerHost host;

        public DistControlServerService(string prefix, string dataDirectory)
        {
            ServiceName = "DistControlServer";
            CanStop = true;
            AutoLog = true;
            this.prefix = prefix;
            this.dataDirectory = dataDirectory;
        }

        protected override void OnStart(string[] args)
        {
            host = new ServerHost(prefix, dataDirectory);
            host.Start();
        }

        protected override void OnStop()
        {
            if (host != null) host.Dispose();
            host = null;
        }

        public void RunConsole()
        {
            OnStart(new string[0]);
            Console.WriteLine("DistControl Server запущен: " + prefix);
            Console.WriteLine("Данные: " + dataDirectory);
            Console.WriteLine("Для остановки нажмите Ctrl+C.");
            using (ManualResetEvent stopped = new ManualResetEvent(false))
            {
                Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e) { e.Cancel = true; stopped.Set(); };
                stopped.WaitOne();
            }
            OnStop();
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            string prefix = "http://+:8765/";
            string dataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DistControlServer");
            bool console = Environment.UserInteractive;

            for (int i = 0; i < args.Length; ++i)
            {
                if (args[i] == "--console") console = true;
                else if (args[i] == "--service") console = false;
                else if (args[i] == "--url" && i + 1 < args.Length) prefix = args[++i];
                else if (args[i] == "--data" && i + 1 < args.Length) dataDirectory = Path.GetFullPath(args[++i]);
            }

            try
            {
                DistControlServerService service = new DistControlServerService(prefix, dataDirectory);
                if (console) service.RunConsole();
                else ServiceBase.Run(service);
                return 0;
            }
            catch (Exception error)
            {
                try
                {
                    Directory.CreateDirectory(dataDirectory);
                    File.AppendAllText(Path.Combine(dataDirectory, "server-error.log"),
                        DateTime.Now.ToString("s") + " " + error + Environment.NewLine);
                }
                catch { }
                if (console) Console.Error.WriteLine(error.ToString());
                return 1;
            }
        }
    }
}
