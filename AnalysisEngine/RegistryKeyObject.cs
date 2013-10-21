using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    class RegistryKeyObject
    {
        private string name;
        private string type;
        private string path;
        private string detection;
        private string key;

        public RegistryKeyObject() { }

        public string KeyName
        {
            get { return name; }
            set { name = value; }
        }


        public string KeyType
        {
            get { return type; }
            set { type = value; }
        }

        public string Path
        {
            get { return path; }
            set { path = value; }
        }

        public string Detection
        {
            get { return detection; }
            set { detection = value; }
        }

        public string Key
        {
            get { return key; }
            set { key = value; }
        }

    }
}
