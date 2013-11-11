using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    public class Writer
    {
        private static StreamWriter writer;
        private static StringBuilder builder = new StringBuilder();
        private static string path;

        private static Writer instance = null;

        public event HandleAddLog LogAdded;

        public delegate void HandleAddLog(object sender, AddLogEventArgs e);

        public static Writer getInstance()
        {
            if (instance == null)
            {
                instance = new Writer();
                return instance;
            }
            else
            {
                return instance;
            }
        }

        public void RaiseLogAdded(AddLogEventArgs e)
        {
            LogAdded(instance, e);
        }

        public void write(string time, string eventstring, string detectstring)
        {
            APEventLogEntry temp = new APEventLogEntry(time, eventstring, detectstring);
            RaiseLogAdded(new AddLogEventArgs(temp));
            //Format will be: (timestamp) Event [what is it],
            builder.Clear();
            builder.Append("(");
            builder.Append(time);
            builder.Append(") ");
            builder.Append(eventstring);
            builder.Append(" [");
            builder.Append(detectstring);
            builder.Append("]");
            builder.Append(",");
            builder.Append(Environment.NewLine);

            using (StreamWriter w = File.AppendText(path))
            {
                w.Write(builder.ToString());
            }
        }

        public void write(string input)
        {

            APEventLogEntry temp = new APEventLogEntry(DateTime.Now.ToLongDateString(), input, "test");
            RaiseLogAdded(new AddLogEventArgs(temp));
        }

        public void setPath(string s)
        {
            if (writer != null)
                writer.Close();


            path = s;
            if (!File.Exists(s))
            {
                writer = new StreamWriter(s);
                writer.Close();
            }
        }
    }
}
