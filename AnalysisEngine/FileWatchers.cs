using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    /// <summary>
    /// Watches particular locations for new files created.
    /// </summary>
    class FileWatchers
    {
        FileSystemWatcher psexecWatcher;
        FileSystemWatcher exploitWatcher;
        FileSystemWatcher systempWatcher;
        
        string sysroot = Environment.ExpandEnvironmentVariables("%SYSTEMROOT%") + "\\";
        string usertemp = System.IO.Path.GetTempPath();
        string systemp;

        Writer w;

        public FileWatchers()
        {
            
            systemp = sysroot + "temp\\";
            //c:\Windows
            psexecWatcher = new FileSystemWatcher();
            psexecWatcher.Path = sysroot;
            psexecWatcher.Filter = "*.*";
            psexecWatcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size;
            psexecWatcher.IncludeSubdirectories = false;
            psexecWatcher.Changed += new FileSystemEventHandler(psexecChanged);
            psexecWatcher.EnableRaisingEvents = true;

            //%temp%
            exploitWatcher = new FileSystemWatcher();
            exploitWatcher.Path = usertemp;
            exploitWatcher.Filter = "*.*";
            exploitWatcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size;
            exploitWatcher.IncludeSubdirectories = true;
            exploitWatcher.Changed += new FileSystemEventHandler(exploitChanged);
            exploitWatcher.EnableRaisingEvents = true;

            //c:\windows\temp
            systempWatcher = new FileSystemWatcher();
            systempWatcher.Path = systemp;
            systempWatcher.Filter = "*.*";
            systempWatcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size;
            systempWatcher.IncludeSubdirectories = false;
            systempWatcher.Changed += new FileSystemEventHandler(systempChanged);
            systempWatcher.EnableRaisingEvents = true;

            w = Writer.getInstance();
        }

        private void psexecChanged(object sender, FileSystemEventArgs e){
            //73802 = Possible Meterpreter
            //15872 = Possible Psexec
            try
            {
                FileInfo f = new FileInfo(e.FullPath);

                string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();

                string detect = "";
                if (f.Length == 73802 && f.Name.Contains(".exe"))
                {
                    detect = "Likely Meterpreter Executable";
                    w.write(date, e.FullPath, detect);
                }
                else if (f.Length == 15872 && f.Name.Contains(".exe"))
                {
                    detect = "Likely PSExec Executable";
                    w.write(date, e.FullPath, detect);
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        private void exploitChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                FileInfo f = new FileInfo(e.FullPath);

                string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();

                string detect = "";
                if (f.Length == 73802 && f.Name.Contains(".exe"))
                {
                    detect = "Likely Meterpreter Executable";
                    w.write(date, e.FullPath, detect);
                }
                else if (f.Length == 15872 && f.Name.Contains(".exe"))
                {
                    detect = "Likely PSExec Executable";
                    w.write(date, e.FullPath, detect);
                }
                else if (f.Length == 148480 && f.Name.Equals("tior.exe"))
                {
                    detect = "BypassUAC Executable";
                    w.write(date, e.FullPath, detect);
                }
                else if (f.Length == 61440 && f.Name.Equals("metsvc.exe"))
                {
                    detect = "Metsvc Installation";
                    w.write(date, e.FullPath, detect);
                }
            }
            catch (Exception)
            {
                return;
            }
            
        }

        private void systempChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                FileInfo f = new FileInfo(e.FullPath);

                string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();

                string detect = "";
                if (f.Length == 73802 && f.Name.Contains(".exe"))
                {
                    detect = "Likely Meterpreter Executable";
                    w.write(date, e.FullPath, detect);
                }
                else if (f.Length == 15872 && f.Name.Contains(".exe"))
                {
                    detect = "Likely PSExec Executable";
                    w.write(date, e.FullPath, detect);
                }
                else if (f.Length == 148480 && f.Name.Equals("tior.exe"))
                {
                    detect = "BypassUAC Executable";
                    w.write(date, e.FullPath, detect);
                }
                else if (f.Length == 61440 && f.Name.Equals("metsvc.exe"))
                {
                    detect = "Metsvc Installation";
                    w.write(date, e.FullPath, detect);
                }
            }
            catch (Exception)
            {
                return;
            }
            
        }
    }
}
