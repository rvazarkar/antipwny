using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    /// <summary>
    /// Class to encapsulate the data we need for Adding an Event Log Entry
    /// </summary>
    public class AddLogEventArgs
    {
        private APEventLogEntry entry;

        public AddLogEventArgs(APEventLogEntry e)
        {
            this.entry = e;
        }

        public APEventLogEntry Entry
        {
            get { return entry; }
            set { entry = value; }
        }
    }
}
