using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using BrightIdeasSoftware;
using System.Net;
using System.Collections;

namespace AnalysisEngine
{
    class AntiPwny : Form
    {
        static RegistryWatchers regwatch;

        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.Run(new AntiPwny());
        }

        private static bool ipsmode = false;
        private Timer timer;
        private MenuStrip antipwnyMenu;
        private ToolStripMenuItem optionsToolStripMenuItem;
        private ToolStripMenuItem runAtStartupToolStripMenuItem;
        private TabControl tabControl;
        private TabPage registryPage;
        private TabPage logPage;

        private NotifyIcon icon;
        private TabPage procPage;
        private System.ComponentModel.BackgroundWorker procListUpdater;
        private InfoProgressBar procProgressBar;
        private IContainer components;
        private TreeListView processTreeView;
        private OLVColumn olvColumn1;
        private OLVColumn olvColumn2;
        private OLVColumn olvColumn3;
        private ToolStripMenuItem exitToolStripMenuItem;
        private ContextMenuStrip processMenuStrip;
        private ToolStripMenuItem killProcessToolStripMenuItem;

        bool isClosing = false;
        int countdown = 60;

        private List<APEventLogEntry> eventLogEntries;
        private ObjectListView evtLogList;
        private OLVColumn olvColumn4;
        private OLVColumn olvColumn5;
        private OLVColumn olvColumn6;
        private ObjectListView registryListView;
        private OLVColumn olvColumn7;
        private OLVColumn olvColumn8;
        private OLVColumn olvColumn10;
        private OLVColumn olvColumn9;
        private ContextMenuStrip registryMenuStrip;
        private ToolStripMenuItem removeRegistryEntryToolStripMenuItem;
        private OLVColumn olvColumn11;
        private Button rescanButton;
        private ToolStripMenuItem iPSModeToolStripMenuItem;
        private TabPage tabPage1;
        private Label label1;
        private TextBox textBox1;

        private delegate void AddItemCallback(object sender, AddLogEventArgs e);
        private delegate void UpdateListCallback(List<ProcessListObject> objects);
        private delegate void UpdateRegistryCallback(object sender, RegistryKeyObject e);
        private delegate void RemoveRegistryCallback(object sender, string s);
        private ProcWatchers proc;
        Writer w;
        StringBuilder builder;

        public AntiPwny()
        {
            icon = new NotifyIcon();
            icon.Text = "Antipwny";
            icon.Icon = new System.Drawing.Icon(System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("AnalysisEngine.Resources.icon.ico"));
            icon.ContextMenu = new ContextMenu();
            icon.ContextMenu.MenuItems.Add("Exit",OnExit);

            icon.DoubleClick += new EventHandler(ShowGui);
            icon.Visible = true;

            InitializeComponent();
            initializeGui();

            w = Writer.getInstance();
            w.LogAdded += HandleItemAdded;
            builder = new StringBuilder();
            
            w.setPath("output.txt");
            FileWatchers filewatch = new FileWatchers();
            regwatch = new RegistryWatchers();
            regwatch.addRegistry += regwatch_addRegistry;
            regwatch.removedEntry += regwatch_removedEntry;
            EventLogWatchers evt = new EventLogWatchers();
            proc = new ProcWatchers();
            rescanButton.Enabled = false;
            procListUpdater.RunWorkerAsync();
        }

        public static bool PreventionMode
        {
            get { return ipsmode; }
            set { ipsmode = value; }
        }

        /// <summary>
        /// Removes an entry from the Registry List
        /// </summary>
        /// <param name="sender">The sender object</param>
        /// <param name="s">The key name we are removing</param>
        void regwatch_removedEntry(object sender, string s)
        {
            if (registryListView.InvokeRequired)
            {
                registryListView.Invoke(new RemoveRegistryCallback(regwatch_removedEntry), new Object[] { sender, s });
            }
            else
            {
                IEnumerable temp = registryListView.Objects;
                foreach (RegistryKeyObject t in temp)
                {
                    if (t.KeyName == s)
                    {
                        registryListView.RemoveObject(t);
                        break;
                    }
                }
                if (registryListView.GetItemCount() == 0)
                    registryListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            }
        }

        /// <summary>
        /// Adds a registry entry to the registry list
        /// </summary>
        /// <param name="sender">The sending object</param>
        /// <param name="e">Encapsulating Object to store our data</param>
        void regwatch_addRegistry(object sender, RegistryKeyObject e)
        {
            if (registryListView.InvokeRequired)
            {
                registryListView.Invoke(new UpdateRegistryCallback(regwatch_addRegistry), new Object[] { sender, e});
            }
            else
            {
                registryListView.AddObject(e);
                registryListView.AutoResizeColumns();
            }
        }

        /// <summary>
        /// Adds an item to our event log
        /// </summary>
        /// <param name="sender">Sending Object</param>
        /// <param name="e">Encapsulating Object with data</param>
        public void HandleItemAdded(object sender, AddLogEventArgs e)
        {
            if (processTreeView.InvokeRequired)
            {
                evtLogList.Invoke(new AddItemCallback(HandleItemAdded), new Object[] {sender, e});
            }
            else
            {
                evtLogList.BeginUpdate();
                evtLogList.AddObject(e.Entry);
                eventLogEntries.Add(e.Entry);
                evtLogList.EndUpdate();
                evtLogList.EnsureVisible(evtLogList.Items.Count - 1);
                if (PreventionMode)
                {
                    icon.BalloonTipTitle = "Intrusion Prevented";
                }
                else
                {
                    icon.BalloonTipTitle = "Event Detected";
                }
                icon.BalloonTipText = e.Entry.Detect;
                icon.ShowBalloonTip(3000);
                if (eventLogEntries.Count == 0)
                {
                    evtLogList.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
                }
                else
                {
                    evtLogList.AutoResizeColumns();
                }
            }
        }

       

        #region Form Events

        private void rescanButton_Click(object sender, EventArgs e)
        {
            timer.Stop();
            rescanButton.Enabled = false;
            procListUpdater.RunWorkerAsync();
        }

        private void iPSModeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item.Checked)
            {
                PreventionMode = false;
                item.Checked = false;
                registryPage.Enabled = true;
                procPage.Enabled = true;
            }
            else
            {
                PreventionMode = true;
                item.Checked = true;
                registryPage.Enabled = false;
                procPage.Enabled = false;
                tabControl.SelectedIndex = 2;
            }
        }

        private void tabControl_Selecting(object sender, TabControlCancelEventArgs e)
        {
            e.Cancel = !e.TabPage.Enabled;
        }
        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            isClosing = true;
            Application.Exit();
        }

        private void killProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            IList list = processTreeView.SelectedObjects;
            foreach (object i in list){
                ProcessListObject obj = i as ProcessListObject;


                Process.EnterDebugMode();
                Process p = Process.GetProcessById(obj.InternalID);

                if (!p.HasExited)
                {
                    try
                    {
                        p.Kill();
                        if (obj.Parent != null)
                        {
                            processTreeView.RemoveObject(obj.Parent);
                        }
                        else
                            processTreeView.RemoveObject(obj);
                    }
                    catch (Exception)
                    {
                        MessageBox.Show("Unable to kill process " + obj.ProcessName);
                    }
                }

                Process.LeaveDebugMode();
            }
            
        }

        private void processTreeView_CellRightClick_1(object sender, CellRightClickEventArgs e)
        {
            if (e.Model != null)
            {
                e.MenuStrip = processMenuStrip;
            }
        }
        private void tabControl_Selected(object sender, TabControlEventArgs e)
        {
            if (tabControl.SelectedIndex == 0)
            {
                procProgressBar.Visible = true;
                rescanButton.Visible = true;
            }
            else
            {
                procProgressBar.Visible = false;
                rescanButton.Visible = false;
            }
        }

        /// <summary>
        /// Sets the status of the Run At Startup menu item before everything else loads.
        /// </summary>
        /// <param name="e"></param>
        protected override void OnLoad(EventArgs e)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);

            object exists = key.GetValue("AntiPwny");
            if (exists == null)
            {
                runAtStartupToolStripMenuItem.Checked = false;
            }
            else
            {
                runAtStartupToolStripMenuItem.Checked = true;
            }
            
            base.OnLoad(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                regwatch.procExit();
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// The real exit function, called from the menu.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnExit(object sender, EventArgs e)
        {
            isClosing = true;
            icon.Visible = false;
            icon.Dispose();
            Application.Exit();
        }

        private void ShowGui(object sender, EventArgs e)
        {
            Visible = true;
            ShowInTaskbar = true;
        }

        /// <summary>
        /// Hook the regular X button in the form to make sure it hides instead of exits unless we have explicitly called our close function
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void AntiPwny_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (!isClosing)
            {
                e.Cancel = true;
                Visible = false;
                ShowInTaskbar = false;
            }
            else
            {
                icon.Visible = false;
                icon.Dispose();
            }
        }

        /// <summary>
        /// Toggles run at startup
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void runAtStartupToolStripMenuItem_Click(object sender, EventArgs e)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
            ToolStripMenuItem menu = (ToolStripMenuItem)sender;
            if (menu.Checked)
            {
                key.DeleteValue("AntiPwny", false);
                menu.Checked = false;
            }
            else
            {
                key.SetValue("AntiPwny", Application.ExecutablePath.ToString());
                menu.Checked = true;
            }
        }

        private void registryListView_CellRightClick(object sender, CellRightClickEventArgs e)
        {
            registryMenuStrip.Show(Cursor.Position);
        }

        private void removeRegistryEntryToolStripMenuItem_Click(object sender, EventArgs e)
        {
            IList list = registryListView.SelectedObjects;
            foreach (object temp in list)
            {
                RegistryKeyObject obj = temp as RegistryKeyObject;
                string path = obj.Key;
                RegistryKey key;
                if (path.StartsWith("HKCU"))
                {
                    path = path.Substring(5);
                    key = Registry.CurrentUser.OpenSubKey(path, true);
                    key.DeleteValue(obj.KeyName, false);
                }
                else
                {
                    path = path.Substring(5);
                    key = Registry.LocalMachine.OpenSubKey(path, true);
                    if (path.ToLower().Contains("service"))
                    {
                        key.DeleteSubKeyTree(obj.KeyName);
                    }
                    else
                        key.DeleteValue(obj.KeyName, false);
                }
                if (obj.KeyName == "AntiPwny")
                    runAtStartupToolStripMenuItem.Checked = false;
                registryListView.RemoveObject(obj);
            }
        }
        #endregion

        #region Process List Stuff
        /// <summary>
        /// Updates the list that displays processes.
        /// </summary>
        /// <param name="objects"></param>
        private void HandleUpdateProcs(List<ProcessListObject> objects)
        {
            if (processTreeView.InvokeRequired)
            {
                processTreeView.Invoke(new UpdateListCallback(HandleUpdateProcs), new Object[] { objects });
            }
            else
            {
                processTreeView.BeginUpdate();
                processTreeView.SetObjects(objects);
                processTreeView.EndUpdate();
                
                if (objects.Count == 0)
                {
                    processTreeView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
                }
                else
                {
                    processTreeView.AutoResizeColumns();
                }
            }
        }

        /// <summary>
        /// The main worker thread that does process scanning. Background this so it doesn't interfere with our main thread.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void procListUpdater_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            //Make sure we're in Debug Mode so we have access to all processes.
            Process.EnterDebugMode();
            //Change our process priority to Below Normal so we don't eat all the CPU time.
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal;
            BackgroundWorker worker = sender as BackgroundWorker;
            List<Process> procs = new List<Process>();
            Process[] all = Process.GetProcesses();

            for (int i = 0; i < all.Length; i++)
            {
                double pct = (double) i / (double) all.Length;
                pct = pct * 100;
                
                Process p = all[i];
                
                //Report our progress as a percentage of the process list completed.
                worker.ReportProgress((int)pct,"");
                
                //It's important to refresh processes before each check. A full scan is time consuming, and process state can often change in between.
                p.Refresh();
                try
                {
                    //Check to make sure our process is still there
                    if (!p.HasExited)
                    {
                        //Filter out ourselves as well as the Windows Defender module. Windows Defender will almost always have the signature we're looking for provided AntiPwny is running
                        if (!p.MainModule.FileName.ToLower().Contains("msmpeng"))
                        {
                            //Use a different scan for Java. We still need to look for meterpreter in java as well, because it can be migrated. This will look specifically for Java Meterpreter
                            if (p.ProcessName == "java")
                            {
                                if (Utilities.scanJava(p))
                                {
                                    procs.Add(p);
                                }
                            }

                            //Scan our process for Meterpreter
                            if (Utilities.scanProcess(p))
                            {
                                procs.Add(p);
                            }
                            
                        }
                    }
                }
                catch (Exception f) { Console.WriteLine("Error opening " + p.ProcessName); Console.WriteLine(f.Message); }
            }

            //Build our TCP table so we have all connections
            MIB_TCPROW_OWNER_PID[] table;

            int inet = 2;
            int buffSize = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, inet, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                ret = GetExtendedTcpTable(buffTable, ref buffSize, true, inet, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0)
                {
                    return;
                }

                // get the number of entries in the table
                MIB_TCPTABLE_OWNER_PID tab = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(buffTable, typeof(MIB_TCPTABLE_OWNER_PID));
                IntPtr rowPtr = (IntPtr)((long)buffTable + Marshal.SizeOf(tab.dwNumEntries));
                table = new MIB_TCPROW_OWNER_PID[tab.dwNumEntries];

                for (int i = 0; i < tab.dwNumEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    table[i] = tcpRow;
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(tcpRow));   // next entry
                }
            }
            finally
            {
                // Free the Memory
                Marshal.FreeHGlobal(buffTable);
            }

            worker.ReportProgress(100, "Scanning Connections");

            //Map connections to PIDs for easier lookup
            Dictionary<int, List<ProcessListObject>> map = new Dictionary<int, List<ProcessListObject>>();
            foreach (MIB_TCPROW_OWNER_PID row in table){
                List<ProcessListObject> list;
                map.TryGetValue(row.owningPid, out list);
                if (list != null)
                {
                    ProcessListObject temp = new ProcessListObject();
                    temp.ProcessName = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString() +" (" + BitConverter.ToUInt16(
                        new byte[2] { row.localPort2, row.localPort1 }, 0) + ")";
                    temp.ProcessID = "->";
                    temp.ProcessPath = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString() + " (" + BitConverter.ToUInt16(
                        new byte[2] { row.localPort2, row.localPort1 }, 0) + ")";
                    list.Add(temp);
                    temp.InternalID = row.owningPid;
                    map.Remove(row.owningPid);
                    map.Add(row.owningPid, list);
                }
                else
                {
                    list = new List<ProcessListObject>();
                    ProcessListObject temp = new ProcessListObject();
                    temp.ProcessName = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString() + " (" + BitConverter.ToUInt16(
                        new byte[2] { row.localPort2, row.localPort1 }, 0) + ")";
                    temp.ProcessID = "->";
                    temp.ProcessPath = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString() + " (" + BitConverter.ToUInt16(
                        new byte[2] { row.localPort2, row.localPort1 }, 0) + ")";
                    list.Add(temp);
                    temp.InternalID = row.owningPid;
                    map.Add(row.owningPid, list);
                }
            }

            List<ProcessListObject> objects = new List<ProcessListObject>();
            List<ProcessListObject> reference;

            //Loop back through the processes we detected with Meterpreter and correlate connections going outbound for display
            foreach (Process p in procs)
            {
                p.Refresh();
                
                if (!p.HasExited)
                {
                    if (PreventionMode)
                    {
                        builder.Clear();
                        builder.Append(p.ProcessName);
                        builder.Append(" Killed");
                        w.write(DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString(), builder.ToString(), "Meterpreter");
                        p.Kill();
                    }
                    else
                    {
                        ProcessListObject temp = new ProcessListObject();
                        temp.ProcessID = p.Id.ToString();
                        temp.ProcessName = p.ProcessName;
                        temp.ProcessPath = p.MainModule.FileName;
                        temp.InternalID = p.Id;
                        temp.Detected = "Meterpreter";

                        map.TryGetValue(p.Id, out reference);
                        if (reference != null)
                        {
                            foreach (ProcessListObject t in reference)
                            {
                                t.Parent = temp;
                            }
                            temp.Connections = reference;

                        }
                        else
                        {
                            temp.Connections = null;
                        }
                        objects.Add(temp);
                    }
                }
            }

            worker.ReportProgress(100, "Scanning cmd.exe");

            //Looking for reverse shells. They usually manifest as cmd.exe with a parent process running that has the actual reverse connection
            foreach (Process p in Process.GetProcessesByName("cmd"))
            {
                Process par = Utilities.ParentProcessUtilities.GetParentProcess(p.Id);
                if (par != null)
                    map.TryGetValue(par.Id, out reference);
                else
                    map.TryGetValue(p.Id, out reference);
                if (reference != null)
                {
                    if (PreventionMode)
                    {
                        p.Kill();
                        w.write(DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString(), "Killed cmd.exe", "Reverse Shell");
                    }
                    else
                    {
                        ProcessListObject temp = new ProcessListObject();
                        temp.ProcessID = p.Id.ToString();
                        temp.ProcessName = p.ProcessName;
                        temp.ProcessPath = p.MainModule.FileName;
                        temp.InternalID = p.Id;
                        temp.Detected = "Reverse Shell";

                        foreach (ProcessListObject t in reference)
                        {
                            t.Parent = temp;
                        }

                        temp.Connections = reference;

                        objects.Add(temp);
                    }
                }
            }

            worker.ReportProgress(100, "Scanning wscript");

            //Look through wscript and cscript, which are almost always used for meterpreter. If we find the command line arguments
            //contain both temp and .vbs, we can be fairly certain this is a persistence script being called.
            foreach (Process p in Process.GetProcessesByName("wscript"))
            {
                string s = Utilities.GetCmdArguments(p);
                if (s.ToLower().Contains("temp") && s.ToLower().Contains(".vbs"))
                {
                    ProcessListObject temp = new ProcessListObject();
                    temp.ProcessID = p.Id.ToString();
                    temp.ProcessName = p.ProcessName;
                    temp.ProcessPath = p.MainModule.FileName;
                    temp.InternalID = p.Id;
                    temp.Detected = "Persistence WScript";
                    temp.Connections = null;
                    objects.Add(temp);
                }
            }

            foreach (Process p in Process.GetProcessesByName("cscript"))
            {
                string s = Utilities.GetCmdArguments(p);
                if (s.ToLower().Contains("temp") && s.ToLower().Contains(".vbs"))
                {
                    ProcessListObject temp = new ProcessListObject();
                    temp.ProcessID = p.Id.ToString();
                    temp.ProcessName = p.ProcessName;
                    temp.ProcessPath = p.MainModule.FileName;
                    temp.InternalID = p.Id;
                    temp.Detected = "Persistence CScript";
                    temp.Connections = null;
                    objects.Add(temp);
                }
            }
            Process.LeaveDebugMode();
            //Exit Debug Mode
            worker.ReportProgress(100, "Waiting :60 Till Next Scan");
            //Report our finished status
            e.Result = objects;
        }
        
        /// <summary>
        /// Called when our background thread finishes
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void procListUpdater_RunWorkerCompleted(object sender, System.ComponentModel.RunWorkerCompletedEventArgs e)
        {
            List<ProcessListObject> p = e.Result as List<ProcessListObject>;
            HandleUpdateProcs(p);
            rescanButton.Enabled = true;
            procProgressBar.ProcName = "Waiting :60 Till Next Scan";
            //Start a countdown waiting 60 seconds to scan again. User can initiate a scan if they so choose
            countdown = 60;
            timer.Start();
        }

        /// <summary>
        /// Counts down time till next automatic scan
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void t_Tick(object sender, EventArgs e)
        {
            countdown --;
            procProgressBar.ProcName = "Waiting :" + countdown + " Till Next Scan";
            procProgressBar.Refresh();
            if (countdown == 0)
            {
                countdown = 60;
                procListUpdater.RunWorkerAsync();
                procProgressBar.ProcName = "";
                Timer t = sender as Timer;
                t.Stop();
            }
        }

        private void procListUpdater_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            procProgressBar.Value = e.ProgressPercentage;
            procProgressBar.ProcName = e.UserState as string;
        }
        #endregion

        #region Initialize
        /// <summary>
        /// Initializes various important parts of the GUI for first view
        /// </summary>
        private void initializeGui()
        {
            processTreeView.CanExpandGetter = delegate(object x)
            {
                if (x is ProcessListObject)
                {
                    ProcessListObject t = (ProcessListObject)x;
                    if (t.Connections != null)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            };

            processTreeView.ChildrenGetter = delegate(object x)
            {
                ProcessListObject t = (ProcessListObject)x;
                return t.Connections;
            };
            timer = new Timer();
            timer.Interval = 1000;
            timer.Tick += t_Tick;

            processTreeView.FullRowSelect = true;

            processTreeView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);

            processTreeView.Expanded += processTreeView_Expanded;

            //Read our current output file in so we have our previous events in our event log
            string path = Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "output.txt");
            eventLogEntries = new List<APEventLogEntry>();
            if (File.Exists(path))
            {
                string[] lines = File.ReadAllLines(path);
                foreach (string line in lines)
                {
                    Match m = Regex.Match(line, "\\((.*)\\) (.*) \\[(.*)\\]");
                    APEventLogEntry entry = new APEventLogEntry(m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value);
                    eventLogEntries.Add(entry);
                }
            }
            evtLogList.ShowGroups = false;
            evtLogList.EmptyListMsg = "No Events Found";
            evtLogList.FullRowSelect = true;
            evtLogList.SetObjects(eventLogEntries);
            if (eventLogEntries.Count > 0)
                evtLogList.EnsureVisible(evtLogList.Items.Count - 1);
            if (eventLogEntries.Count == 0)
                evtLogList.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            else
                evtLogList.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);

            List<RegistryKeyObject> objects = new List<RegistryKeyObject>();
            
            //Open our registry keys and enumerate entries that we are fairly positive are persistence entries
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");

            foreach (string s in key.GetValueNames())
            {
                if (key.GetValue(s).ToString().Contains(".vbs"))
                {
                    RegistryKeyObject temp = new RegistryKeyObject();
                    temp.Detection = "Persistence";
                    temp.KeyName = s;
                    temp.KeyType = "User Startup";
                    temp.Path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + s;
                    temp.Key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\";

                    objects.Add(temp);
                }
            }

            key = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");

            foreach (string s in key.GetValueNames())
            {
                string val = key.GetValue(s) as string;
                if (val != null)
                {
                    if (val.ToString().Contains(".vbs"))
                    {
                        RegistryKeyObject temp = new RegistryKeyObject();
                        temp.Detection = "Persistence";
                        temp.KeyName = s;
                        temp.KeyType = "System Startup";
                        temp.Path = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + s;
                        temp.Key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\";

                        objects.Add(temp);
                    }
                }
            }

            //Open services and look for persistence
            key = Registry.LocalMachine.OpenSubKey("System\\CurrentControlSet\\services");
            foreach (string s in key.GetSubKeyNames())
            {
                RegistryKey t = key.OpenSubKey(s);
                string p = t.GetValue("ImagePath") as string;
                if (p != null)
                {
                    if (p.Contains(".vbs") && p.Contains("cscript"))
                    {
                        RegistryKeyObject temp = new RegistryKeyObject();
                        temp.Detection = "Persistence";
                        temp.KeyName = s;
                        temp.KeyType = "Service";
                        temp.Path = "HKLM\\System\\CurrentControlSet\\services\\" + s;
                        temp.Key = "HKLM\\System\\CurrentControlSet\\services\\";

                        objects.Add(temp);
                    }
                    else if (p.Contains("metsvc"))
                    {
                        RegistryKeyObject temp = new RegistryKeyObject();
                        temp.Detection = "MetSvc";
                        temp.KeyName = s;
                        temp.KeyType = "Service";
                        temp.Path = "HKLM\\System\\CurrentControlSet\\services\\" + s;
                        temp.Key = "HKLM\\System\\CurrentControlSet\\services\\";

                        objects.Add(temp);
                    }
                }
            }

            registryListView.FullRowSelect = true;
            registryListView.EmptyListMsg = "No Registry Keys Found";
            registryListView.ShowGroups = false;
            registryListView.SetObjects(objects);
            if (objects.Count == 0)
                registryListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            else
                registryListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
        }

        void processTreeView_CellRightClick(object sender, CellRightClickEventArgs e)
        {
            processMenuStrip.Show(Cursor.Position);
        }

        void processTreeView_Expanded(object sender, TreeBranchExpandedEventArgs e)
        {
            processTreeView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AntiPwny));
            this.antipwnyMenu = new System.Windows.Forms.MenuStrip();
            this.optionsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.runAtStartupToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.iPSModeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.procPage = new System.Windows.Forms.TabPage();
            this.processTreeView = new BrightIdeasSoftware.TreeListView();
            this.olvColumn11 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn1 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn2 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn3 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.registryPage = new System.Windows.Forms.TabPage();
            this.registryListView = new BrightIdeasSoftware.ObjectListView();
            this.olvColumn7 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn8 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn10 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn9 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.logPage = new System.Windows.Forms.TabPage();
            this.evtLogList = new BrightIdeasSoftware.ObjectListView();
            this.olvColumn5 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn4 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.olvColumn6 = ((BrightIdeasSoftware.OLVColumn)(new BrightIdeasSoftware.OLVColumn()));
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.processMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.killProcessToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.procListUpdater = new System.ComponentModel.BackgroundWorker();
            this.registryMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.removeRegistryEntryToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.procProgressBar = new AnalysisEngine.InfoProgressBar();
            this.rescanButton = new System.Windows.Forms.Button();
            this.antipwnyMenu.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.procPage.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.processTreeView)).BeginInit();
            this.registryPage.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.registryListView)).BeginInit();
            this.logPage.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.evtLogList)).BeginInit();
            this.tabPage1.SuspendLayout();
            this.processMenuStrip.SuspendLayout();
            this.registryMenuStrip.SuspendLayout();
            this.SuspendLayout();
            // 
            // antipwnyMenu
            // 
            this.antipwnyMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.optionsToolStripMenuItem});
            this.antipwnyMenu.Location = new System.Drawing.Point(0, 0);
            this.antipwnyMenu.Name = "antipwnyMenu";
            this.antipwnyMenu.Size = new System.Drawing.Size(1023, 24);
            this.antipwnyMenu.TabIndex = 0;
            this.antipwnyMenu.Text = "menuStrip1";
            // 
            // optionsToolStripMenuItem
            // 
            this.optionsToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.runAtStartupToolStripMenuItem,
            this.iPSModeToolStripMenuItem,
            this.exitToolStripMenuItem});
            this.optionsToolStripMenuItem.Name = "optionsToolStripMenuItem";
            this.optionsToolStripMenuItem.Size = new System.Drawing.Size(61, 20);
            this.optionsToolStripMenuItem.Text = "Options";
            // 
            // runAtStartupToolStripMenuItem
            // 
            this.runAtStartupToolStripMenuItem.Name = "runAtStartupToolStripMenuItem";
            this.runAtStartupToolStripMenuItem.Size = new System.Drawing.Size(149, 22);
            this.runAtStartupToolStripMenuItem.Text = "Run at Startup";
            this.runAtStartupToolStripMenuItem.Click += new System.EventHandler(this.runAtStartupToolStripMenuItem_Click);
            // 
            // iPSModeToolStripMenuItem
            // 
            this.iPSModeToolStripMenuItem.Name = "iPSModeToolStripMenuItem";
            this.iPSModeToolStripMenuItem.Size = new System.Drawing.Size(149, 22);
            this.iPSModeToolStripMenuItem.Text = "IPS Mode";
            this.iPSModeToolStripMenuItem.Click += new System.EventHandler(this.iPSModeToolStripMenuItem_Click);
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(149, 22);
            this.exitToolStripMenuItem.Text = "Exit";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
            // 
            // tabControl
            // 
            this.tabControl.Controls.Add(this.procPage);
            this.tabControl.Controls.Add(this.registryPage);
            this.tabControl.Controls.Add(this.logPage);
            this.tabControl.Controls.Add(this.tabPage1);
            this.tabControl.Location = new System.Drawing.Point(13, 27);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            this.tabControl.Size = new System.Drawing.Size(998, 361);
            this.tabControl.SizeMode = System.Windows.Forms.TabSizeMode.FillToRight;
            this.tabControl.TabIndex = 1;
            this.tabControl.Selecting += new System.Windows.Forms.TabControlCancelEventHandler(this.tabControl_Selecting);
            this.tabControl.Selected += new System.Windows.Forms.TabControlEventHandler(this.tabControl_Selected);
            // 
            // procPage
            // 
            this.procPage.Controls.Add(this.processTreeView);
            this.procPage.Location = new System.Drawing.Point(4, 22);
            this.procPage.Name = "procPage";
            this.procPage.Padding = new System.Windows.Forms.Padding(3);
            this.procPage.Size = new System.Drawing.Size(990, 335);
            this.procPage.TabIndex = 3;
            this.procPage.Text = "Compromised Procs";
            this.procPage.UseVisualStyleBackColor = true;
            // 
            // processTreeView
            // 
            this.processTreeView.AllColumns.Add(this.olvColumn11);
            this.processTreeView.AllColumns.Add(this.olvColumn1);
            this.processTreeView.AllColumns.Add(this.olvColumn2);
            this.processTreeView.AllColumns.Add(this.olvColumn3);
            this.processTreeView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.olvColumn11,
            this.olvColumn1,
            this.olvColumn2,
            this.olvColumn3});
            this.processTreeView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.processTreeView.EmptyListMsg = "No Processes Available";
            this.processTreeView.Location = new System.Drawing.Point(3, 3);
            this.processTreeView.Name = "processTreeView";
            this.processTreeView.OwnerDraw = true;
            this.processTreeView.ShowGroups = false;
            this.processTreeView.Size = new System.Drawing.Size(984, 329);
            this.processTreeView.TabIndex = 1;
            this.processTreeView.UseCompatibleStateImageBehavior = false;
            this.processTreeView.View = System.Windows.Forms.View.Details;
            this.processTreeView.VirtualMode = true;
            this.processTreeView.CellRightClick += new System.EventHandler<BrightIdeasSoftware.CellRightClickEventArgs>(this.processTreeView_CellRightClick_1);
            // 
            // olvColumn11
            // 
            this.olvColumn11.AspectName = "Detected";
            this.olvColumn11.CellPadding = null;
            this.olvColumn11.Text = "Type";
            // 
            // olvColumn1
            // 
            this.olvColumn1.AspectName = "ProcessName";
            this.olvColumn1.CellPadding = null;
            this.olvColumn1.IsEditable = false;
            this.olvColumn1.Text = "Process/Local Address";
            // 
            // olvColumn2
            // 
            this.olvColumn2.AspectName = "ProcessID";
            this.olvColumn2.CellPadding = null;
            this.olvColumn2.IsEditable = false;
            this.olvColumn2.Text = "PID";
            // 
            // olvColumn3
            // 
            this.olvColumn3.AspectName = "ProcessPath";
            this.olvColumn3.CellPadding = null;
            this.olvColumn3.IsEditable = false;
            this.olvColumn3.Text = "Location/Remote Address";
            // 
            // registryPage
            // 
            this.registryPage.Controls.Add(this.registryListView);
            this.registryPage.Location = new System.Drawing.Point(4, 22);
            this.registryPage.Name = "registryPage";
            this.registryPage.Padding = new System.Windows.Forms.Padding(3);
            this.registryPage.Size = new System.Drawing.Size(990, 335);
            this.registryPage.TabIndex = 1;
            this.registryPage.Text = "Registry";
            this.registryPage.UseVisualStyleBackColor = true;
            // 
            // registryListView
            // 
            this.registryListView.AllColumns.Add(this.olvColumn7);
            this.registryListView.AllColumns.Add(this.olvColumn8);
            this.registryListView.AllColumns.Add(this.olvColumn10);
            this.registryListView.AllColumns.Add(this.olvColumn9);
            this.registryListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.olvColumn7,
            this.olvColumn8,
            this.olvColumn10,
            this.olvColumn9});
            this.registryListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.registryListView.Location = new System.Drawing.Point(3, 3);
            this.registryListView.Name = "registryListView";
            this.registryListView.Size = new System.Drawing.Size(984, 329);
            this.registryListView.TabIndex = 0;
            this.registryListView.UseCompatibleStateImageBehavior = false;
            this.registryListView.View = System.Windows.Forms.View.Details;
            this.registryListView.CellRightClick += new System.EventHandler<BrightIdeasSoftware.CellRightClickEventArgs>(this.registryListView_CellRightClick);
            // 
            // olvColumn7
            // 
            this.olvColumn7.AspectName = "KeyName";
            this.olvColumn7.CellPadding = null;
            this.olvColumn7.Text = "Key Name";
            // 
            // olvColumn8
            // 
            this.olvColumn8.AspectName = "KeyType";
            this.olvColumn8.CellPadding = null;
            this.olvColumn8.Text = "Key Type";
            // 
            // olvColumn10
            // 
            this.olvColumn10.AspectName = "Detection";
            this.olvColumn10.CellPadding = null;
            this.olvColumn10.Text = "Detection";
            // 
            // olvColumn9
            // 
            this.olvColumn9.AspectName = "Path";
            this.olvColumn9.CellPadding = null;
            this.olvColumn9.Text = "Full Path";
            // 
            // logPage
            // 
            this.logPage.Controls.Add(this.evtLogList);
            this.logPage.Location = new System.Drawing.Point(4, 22);
            this.logPage.Name = "logPage";
            this.logPage.Size = new System.Drawing.Size(990, 335);
            this.logPage.TabIndex = 2;
            this.logPage.Text = "Event Log";
            this.logPage.UseVisualStyleBackColor = true;
            // 
            // evtLogList
            // 
            this.evtLogList.AllColumns.Add(this.olvColumn5);
            this.evtLogList.AllColumns.Add(this.olvColumn4);
            this.evtLogList.AllColumns.Add(this.olvColumn6);
            this.evtLogList.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.olvColumn5,
            this.olvColumn4,
            this.olvColumn6});
            this.evtLogList.Dock = System.Windows.Forms.DockStyle.Fill;
            this.evtLogList.Location = new System.Drawing.Point(0, 0);
            this.evtLogList.Name = "evtLogList";
            this.evtLogList.Size = new System.Drawing.Size(990, 335);
            this.evtLogList.TabIndex = 0;
            this.evtLogList.UseCompatibleStateImageBehavior = false;
            this.evtLogList.View = System.Windows.Forms.View.Details;
            // 
            // olvColumn5
            // 
            this.olvColumn5.AspectName = "Time";
            this.olvColumn5.CellPadding = null;
            this.olvColumn5.Text = "Time";
            // 
            // olvColumn4
            // 
            this.olvColumn4.AspectName = "Event";
            this.olvColumn4.CellPadding = null;
            this.olvColumn4.Text = "Event";
            // 
            // olvColumn6
            // 
            this.olvColumn6.AspectName = "Detect";
            this.olvColumn6.CellPadding = null;
            this.olvColumn6.Text = "Detect";
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.textBox1);
            this.tabPage1.Controls.Add(this.label1);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(990, 335);
            this.tabPage1.TabIndex = 4;
            this.tabPage1.Text = "Configuration";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(365, 39);
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(450, 20);
            this.textBox1.TabIndex = 1;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(101, 39);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(69, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "Event Logfile";
            // 
            // processMenuStrip
            // 
            this.processMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.killProcessToolStripMenuItem});
            this.processMenuStrip.Name = "contextMenuStrip1";
            this.processMenuStrip.Size = new System.Drawing.Size(134, 26);
            // 
            // killProcessToolStripMenuItem
            // 
            this.killProcessToolStripMenuItem.Name = "killProcessToolStripMenuItem";
            this.killProcessToolStripMenuItem.Size = new System.Drawing.Size(133, 22);
            this.killProcessToolStripMenuItem.Text = "Kill Process";
            this.killProcessToolStripMenuItem.Click += new System.EventHandler(this.killProcessToolStripMenuItem_Click);
            // 
            // procListUpdater
            // 
            this.procListUpdater.WorkerReportsProgress = true;
            this.procListUpdater.DoWork += new System.ComponentModel.DoWorkEventHandler(this.procListUpdater_DoWork);
            this.procListUpdater.ProgressChanged += new System.ComponentModel.ProgressChangedEventHandler(this.procListUpdater_ProgressChanged);
            this.procListUpdater.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.procListUpdater_RunWorkerCompleted);
            // 
            // registryMenuStrip
            // 
            this.registryMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.removeRegistryEntryToolStripMenuItem});
            this.registryMenuStrip.Name = "registryMenuStrip";
            this.registryMenuStrip.Size = new System.Drawing.Size(193, 26);
            // 
            // removeRegistryEntryToolStripMenuItem
            // 
            this.removeRegistryEntryToolStripMenuItem.Name = "removeRegistryEntryToolStripMenuItem";
            this.removeRegistryEntryToolStripMenuItem.Size = new System.Drawing.Size(192, 22);
            this.removeRegistryEntryToolStripMenuItem.Text = "Remove Registry Entry";
            this.removeRegistryEntryToolStripMenuItem.Click += new System.EventHandler(this.removeRegistryEntryToolStripMenuItem_Click);
            // 
            // procProgressBar
            // 
            this.procProgressBar.Location = new System.Drawing.Point(17, 394);
            this.procProgressBar.Name = "procProgressBar";
            this.procProgressBar.ProcName = "";
            this.procProgressBar.Size = new System.Drawing.Size(909, 23);
            this.procProgressBar.TabIndex = 2;
            // 
            // rescanButton
            // 
            this.rescanButton.Location = new System.Drawing.Point(932, 394);
            this.rescanButton.Name = "rescanButton";
            this.rescanButton.Size = new System.Drawing.Size(75, 23);
            this.rescanButton.TabIndex = 3;
            this.rescanButton.Text = "Rescan";
            this.rescanButton.UseVisualStyleBackColor = true;
            this.rescanButton.Click += new System.EventHandler(this.rescanButton_Click);
            // 
            // AntiPwny
            // 
            this.ClientSize = new System.Drawing.Size(1023, 436);
            this.Controls.Add(this.rescanButton);
            this.Controls.Add(this.procProgressBar);
            this.Controls.Add(this.tabControl);
            this.Controls.Add(this.antipwnyMenu);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.antipwnyMenu;
            this.Name = "AntiPwny";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.AntiPwny_FormClosing);
            this.antipwnyMenu.ResumeLayout(false);
            this.antipwnyMenu.PerformLayout();
            this.tabControl.ResumeLayout(false);
            this.procPage.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.processTreeView)).EndInit();
            this.registryPage.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.registryListView)).EndInit();
            this.logPage.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.evtLogList)).EndInit();
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.processMenuStrip.ResumeLayout(false);
            this.registryMenuStrip.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }
        #endregion  

        #region TCP Imports
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            MIB_TCPROW_OWNER_PID table;
        }

        enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tblClass, int reserved);
        #endregion
    }
}
