using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    class RegistryWatchers
    {
        Dictionary<string, string> currentUserReg = new Dictionary<string, string>();
        Dictionary<string, string> localMachineReg = new Dictionary<string, string>();
        Dictionary<string, string> serviceReg = new Dictionary<string, string>();
        string bootSql = @"SELECT * FROM RegistryTreeChangeEvent WHERE HIVE='HKEY_LOCAL_MACHINE'
            AND RootPath = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'";
        string serviceSql = @"SELECT * FROM RegistryKeyChangeEvent WHERE HIVE='HKEY_LOCAL_MACHINE'
            AND KeyPath = 'SYSTEM\\CurrentControlSet\\services'";

        ManagementEventWatcher userWatch = new ManagementEventWatcher();
        ManagementEventWatcher bootWatch = new ManagementEventWatcher();
        ManagementEventWatcher serviceWatch = new ManagementEventWatcher();
        StringBuilder builder = new StringBuilder();
        Writer w;


        public event NewRegistryLog addRegistry;
        public delegate void NewRegistryLog(object sender, RegistryKeyObject e);

        public event DeleteRegistryLog removedEntry;
        public delegate void DeleteRegistryLog(object sender, String s);

        public RegistryWatchers()
        {
            WqlEventQuery bootQuery = new WqlEventQuery(bootSql);
            WqlEventQuery serviceQuery = new WqlEventQuery(serviceSql);
            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
            WqlEventQuery userQuery = new WqlEventQuery("SELECT * FROM RegistryTreeChangeEvent WHERE " +
                            "Hive = 'HKEY_USERS' " +
                             @"AND RootPath = '" + currentUser.User.Value + @"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'");

            userWatch.Query = userQuery;
            bootWatch.Query = bootQuery;
            serviceWatch.Query = serviceQuery;

            userWatch.EventArrived += new EventArrivedEventHandler(currentUserEvent);
            userWatch.Start();

            bootWatch.EventArrived += new EventArrivedEventHandler(localMachineEvent);
            bootWatch.Start();

            serviceWatch.EventArrived += new EventArrivedEventHandler(serviceEvent);
            serviceWatch.Start();
            initialize();
            w = Writer.getInstance();
        }

        private void initialize()
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            foreach (string s in key.GetValueNames())
            {
                currentUserReg.Add(s,Convert.ToString(key.GetValue(s)));
            }

            key = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            foreach (string s in key.GetValueNames())
            {
                localMachineReg.Add(s, Convert.ToString(key.GetValue(s)));
            }

            key = Registry.LocalMachine.OpenSubKey("System\\CurrentControlSet\\services");
            foreach (string s in key.GetSubKeyNames())
            {
                RegistryKey temp = key.OpenSubKey(s);
                string path = temp.GetValue("ImagePath") as string;
                serviceReg.Add(s, path);
            }
        }

        private void serviceEvent(object sender, EventArrivedEventArgs e)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey("System\\CurrentControlSet\\services");
            List<string> keys = new List<string>();
            foreach (string s in key.GetSubKeyNames())
            {
                RegistryKey temp = key.OpenSubKey(s);
                string path = temp.GetValue("ImagePath") as string;
                keys.Add(s);
                if (!serviceReg.ContainsKey(s))
                {
                    serviceReg.Add(s, path);
                    string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();
                    if (path.Contains("cscript") && path.Contains(".vbs")){                    
                    
                        builder.Clear();
                        builder.Append("HKLM\\System\\CurrentControlSet\\services\\");
                        builder.Append(s);
                        builder.Append(" - ");
                        builder.Append(path);

                        w.write(date, builder.ToString(), "Meterpreter Persistence Service");
                        RegistryKeyObject evt = new RegistryKeyObject();
                        evt.Key = "HKLM\\System\\CurrentControlSet\\services";
                        evt.KeyName = s;
                        evt.Detection = "Persistence";
                        evt.KeyType = "Service";
                        evt.Path = "HKLM\\System\\CurrentControlSet\\services\\" + s;
                        addRegistry(this, evt);
                    }else if (path.Contains("metsvc"))
                    {
                        builder.Clear();
                        builder.Append("HKLM\\System\\CurrentControlSet\\services\\");
                        builder.Append(s);
                        builder.Append(" - ");
                        builder.Append(path);

                        w.write(date, builder.ToString(), "Metsvc Registry Entry");

                        RegistryKeyObject evt = new RegistryKeyObject();
                        evt.Key = "HKLM\\System\\CurrentControlSet\\services";
                        evt.KeyName = s;
                        evt.Detection = "Metsvc";
                        evt.KeyType = "Service";
                        evt.Path = "HKLM\\System\\CurrentControlSet\\services\\" + s;
                        addRegistry(this, evt);
                    }
                }
            }

            List<string> toremove = new List<string>();

            foreach (string s in serviceReg.Keys)
            {
                if (!keys.Contains(s))
                    toremove.Add(s);
            }

            foreach (string s in toremove)
            {
                serviceReg.Remove(s);
                removedEntry(this,s);
            }
        }

        private void currentUserEvent(object sender, EventArrivedEventArgs e)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            foreach (string v in key.GetValueNames())
            {
                if (!currentUserReg.ContainsKey(v))
                {
                    string value = Convert.ToString(key.GetValue(v));

                    builder.Clear();
                    builder.Append("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\");
                    builder.Append(v);
                    builder.Append(" - ");
                    builder.Append(value);

                    string detect = "";
                    if (value.Contains(".vbs"))
                    {
                        detect = "User Persistence";
                    }
                    else
                    {
                        detect = "New Startup Item";
                    }

                    RegistryKeyObject evt = new RegistryKeyObject();
                    evt.Key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
                    evt.KeyName = v;
                    evt.Detection = "Persistence";
                    evt.KeyType = "User Startup";
                    evt.Path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + v;
                    addRegistry(this, evt);

                    string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();
                    w.write(date, builder.ToString(), detect);

                    currentUserReg.Add(v, value);
                }
            }

            List<string> toremove = new List<string>();

            foreach (string val in currentUserReg.Keys)
            {
                if (!key.GetValueNames().Contains(val))
                {
                    toremove.Add(val);
                }
            }

            foreach (string val in toremove)
            {
                currentUserReg.Remove(val);
                removedEntry(this, val);
            }
        }

        private void localMachineEvent(object sender, EventArrivedEventArgs e)
        {
            Console.WriteLine("Event");
            RegistryKey key = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            foreach (string v in key.GetValueNames())
            {
                if (!localMachineReg.ContainsKey(v))
                {
                    Console.WriteLine("New Entry");
                    string value = Convert.ToString(key.GetValue(v));

                    builder.Clear();
                    builder.Append("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                    builder.Append(v);
                    builder.Append(" - ");
                    builder.Append(value);

                    string detect = "";
                    if (value.Contains(".vbs")){
                        detect = "System Persistence";
                    }else{
                        detect = "New Startup Item";
                    }

                    RegistryKeyObject evt = new RegistryKeyObject();
                    evt.Key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\";
                    evt.KeyName = v;
                    evt.Detection = "Persistence";
                    evt.KeyType = "System Startup";
                    evt.Path = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + v;
                    addRegistry(this, evt);

                    string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();
                    w.write(date, builder.ToString(), detect);

                    localMachineReg.Add(v, value);
                }
            }

            List<string> toremove = new List<string>();

            foreach (string val in localMachineReg.Keys)
            {
                if (!key.GetValueNames().Contains(val))
                {
                    toremove.Add(val);
                }
            }

            foreach (string val in toremove)
            {
                localMachineReg.Remove(val);
                removedEntry(this, val);
            }
        }

        public void procExit()
        {
            userWatch.Stop();
            bootWatch.Stop();
            serviceWatch.Stop();
        }
    }
}
