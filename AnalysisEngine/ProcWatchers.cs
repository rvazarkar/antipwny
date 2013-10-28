using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace AnalysisEngine
{
    /// <summary>
    /// Watches process creation
    /// </summary>
    class ProcWatchers
    {
        ManagementEventWatcher watcher;
        Writer w;
        StringBuilder builder;


        public ProcWatchers()
        {
            //Hook WMI because its awesome
            watcher = new ManagementEventWatcher();
            WqlEventQuery query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            watcher.Query = query;
            watcher.EventArrived += new EventArrivedEventHandler(watcher_EventArrived);
            watcher.Start();
            w = Writer.getInstance();
            builder = new StringBuilder();
        }

        /// <summary>
        /// Called every time a new process is created
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void watcher_EventArrived(object sender, EventArrivedEventArgs e)
        {
            string type = e.NewEvent.ClassPath.ClassName;

            try
            {
                Process p = Process.GetProcessById(Convert.ToInt32(e.NewEvent.Properties["ProcessId"].Value));

                if (p.ProcessName != "AntiPwny")
                {
                    string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();
                    Timer t = new Timer();
                    //It takes a bit of time for Meterpreter to properly load itself into memory. Wait 7 seconds before we scan the process
                    t.Interval = 7000;
                    t.Elapsed += (s, args) => t_Elapsed(s, args, p, date);
                    t.Start();
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public void t_Elapsed(object sender, ElapsedEventArgs e, Process p, string date)
        {
            Timer t = (Timer)sender;
            t.Stop();
            
            if (p.ProcessName == "java")
            {
                if (Utilities.scanProcess(p))
                {
                    if (AntiPwny.PreventionMode)
                    {
                        builder.Clear();
                        builder.Append(p.ProcessName);
                        builder.Append(" Killed.");
                        p.Kill();

                        w.write(date, builder.ToString(), "Java Meterpreter");
                    }
                    else
                    {
                        builder.Clear();
                        builder.Append(p.ProcessName);
                        builder.Append(" memory contains java meterpreter signature.");

                        w.write(date, builder.ToString(), "Java Meterpreter Found");
                    }
                }
            }
            if (Utilities.scanProcess(p))
            {
                if (AntiPwny.PreventionMode)
                {
                    builder.Clear();
                    builder.Append(p.ProcessName);
                    builder.Append(" Killed.");
                    p.Kill();

                    w.write(date, builder.ToString(), "Meterpreter");
                }
                else
                {
                    builder.Clear();
                    builder.Append(p.ProcessName);
                    builder.Append(" memory contains meterpreter signature.");

                    w.write(date, builder.ToString(), "Meterpreter Found");
                }
            }
        }
    }
}
