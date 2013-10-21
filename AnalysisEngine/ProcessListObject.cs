using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    class ProcessListObject
    {
        private string procname;
        private string procid;
        private string location;
        private int internalid;
        private string detected;

        private ProcessListObject parent;
        private List<ProcessListObject> connections;

        public ProcessListObject() { }

        public ProcessListObject Parent
        {
            get { return parent; }
            set { parent = value; }
        }

        public int InternalID
        {
            get { return internalid; }
            set { internalid = value; }
        }

        public string ProcessName
        {
            get { return procname; }
            set { procname = value; }
        }

        public string ProcessID
        {
            get { return procid; }
            set { procid = value; }
        }

        public string ProcessPath
        {
            get { return location; }
            set { location = value; }
        }

        public List<ProcessListObject> Connections
        {
            get { return connections; }
            set { connections = value; }
        }

        public string Detected
        {
            get { return detected; }
            set { detected = value; }
        }
    }
}
