using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    /// <summary>
    /// Event Log Entry
    /// </summary>
    public class APEventLogEntry
    {
        private string time;
        private string evt;
        private string detect;

        public APEventLogEntry() { }

        public APEventLogEntry(string time, string evt, string detect)
        {
            Time = time;
            Event = evt;
            Detect = detect;
        }

        public string Time
        {
            get { return time; }
            set { time = value; }
        }

        public string Event
        { 
            get { return evt; }
            set { evt = value; }
        }

        public string Detect
        {
            get { return detect; }
            set { detect = value; }
        }
    }
}
