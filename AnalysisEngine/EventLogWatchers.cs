using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    /// <summary>
    /// Class that watches new Event Log Entries in the Security Log
    /// </summary>
    class EventLogWatchers
    {
        string myip;
        StringBuilder builder;
        Writer w;

        public EventLogWatchers()
        {
            EventLog evtLog = new EventLog("Security");
            evtLog.EntryWritten += new EntryWrittenEventHandler(entryWritten);
            evtLog.EnableRaisingEvents = true;
            builder = new StringBuilder();
            w = Writer.getInstance();
        }

        private void initialize()
        {
            IPHostEntry entry;
            entry = Dns.GetHostEntry(Dns.GetHostName());
            myip = entry
                .AddressList
                .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork).ToString();
        }

        /// <summary>
        /// Called Every time a new Event Log entry is written
        /// </summary>
        /// <param name="source"></param>
        /// <param name="e"></param>
        public void entryWritten(object source, EntryWrittenEventArgs e)
        {
            EventLogEntry entry = e.Entry;

            string date = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();

            if (entry.EntryType.ToString() == "SuccessAudit")
            {
                //Successful Logon
                if (entry.InstanceId == 4624)
                {
                    Match logonType = Regex.Match(entry.Message, @"Logon Type:(.*)");

                    if (logonType.Success)
                    {
                        int type = Convert.ToInt32(logonType.Groups[1].Value);
                        if (type == 10)
                        {
                            Match m = Regex.Match(entry.Message, @"Source Network Address:(.*)");

                            if (m.Success)
                            {
                                string key = m.Groups[1].Value;
                                key = key.Replace(" ", string.Empty);
                                key = key.Replace("\t", string.Empty);
                                key = key.Replace("\r", string.Empty);
                                key = key.Replace("\n", string.Empty);
                                if (!key.Contains("-"))
                                {
                                    w.write(date, "RDP Logon from " + key, "Remote RDP Logon");    
                                }
                            }
                        }
                    }
                }
                else if (entry.InstanceId == 4724)
                {
                    //Password Change
                    Match target = Regex.Match(entry.Message, @"Account Name:(.*)");

                    if (target.Success)
                    {
                        target = target.NextMatch();
                        string key = target.Groups[1].Value;
                        key = key.Replace(" ", string.Empty);
                        key = key.Replace("\t", string.Empty);
                        key = key.Replace("\n", string.Empty);

                        w.write(date, "Password was changed for " + key, "Password Change");
                    }
                }
                else if (entry.InstanceId == 4722)
                {
                    //User Created
                    string user;
                    string domain;
                    string creator;

                    user = Regex.Match(entry.Message, @"Account Name:(.*)").NextMatch().Groups[1].Value.Replace(" ",string.Empty).Replace("\t",string.Empty);
                    domain = Regex.Match(entry.Message, @"Account Domain:(.*)").Groups[1].Value.Replace(" ", string.Empty).Replace("\t", string.Empty);
                    creator = Regex.Match(entry.Message, @"Account Name:(.*)").Groups[1].Value.Replace(" ", string.Empty).Replace("\t", string.Empty);

                    builder.Clear();

                    builder.Append("User ");
                    builder.Append(user);
                    builder.Append(" in domain ");
                    builder.Append(domain);
                    builder.Append(" created by ");
                    builder.Append(creator);

                    w.write(date, builder.ToString(), "User Created");
                }
                else if (entry.InstanceId == 4726)
                {
                    //User Deleted
                    string user;
                    string domain;
                    string creator;

                    user = Regex.Match(entry.Message, @"Account Name:(.*)").NextMatch().Groups[1].Value.Replace(" ", string.Empty).Replace("\t", string.Empty);
                    domain = Regex.Match(entry.Message, @"Account Domain:(.*)").Groups[1].Value.Replace(" ", string.Empty).Replace("\t", string.Empty);
                    creator = Regex.Match(entry.Message, @"Account Name:(.*)").Groups[1].Value.Replace(" ", string.Empty).Replace("\t", string.Empty);

                    builder.Clear();

                    builder.Append("User ");
                    builder.Append(user);
                    builder.Append(" in domain ");
                    builder.Append(domain);
                    builder.Append(" deleted by ");
                    builder.Append(creator);

                    w.write(date, builder.ToString(), "User Deleted");
                }
                else if (entry.InstanceId == 7035)
                {
                    //Service Installed (Needs to be implemented)
                }
                else if (entry.InstanceId == 4634)
                {
                    //PSExec Logoff
                    Match logonType = Regex.Match(entry.Message, @"Logon Type:(.*)");

                    if (logonType.Success)
                    {
                        int type = Convert.ToInt32(logonType.Groups[1].Value);
                        if (type == 3)
                        {
                            Match m = Regex.Match(entry.Message, @"Source Network Address:(.*)");
                            Match user = Regex.Match(entry.Message, @"Account Name:(.*)");
                            if (!user.Groups[1].Value.Contains("ANONYMOUS LOGON"))
                            {
                                if (m.Success)
                                {
                                    string key = m.Groups[1].Value;
                                    key = key.Replace(" ", string.Empty);
                                    key = key.Replace("\t", string.Empty);
                                    key = key.Replace("\r", string.Empty);
                                    key = key.Replace("\n", string.Empty);
                                    if (!key.Contains("-"))
                                    {
                                        w.write(date, "PSExec Logon from " + key, "PSExec Logon");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
