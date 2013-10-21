using System;
using System.Drawing;
using System.ComponentModel;
using System.Collections;
using System.Diagnostics;
using System.Windows.Forms;

namespace AnalysisEngine
{
    class BetterListView : ListView
    {
        bool _b = true;
        string message;

        public BetterListView()
        {
            //Activate double buffering
            //this.SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);

            //Enable the OnNotifyMessage event so we get a chance to filter out 
            // Windows messages before they get to the form's WndProc
            this.SetStyle(ControlStyles.EnableNotifyMessage, true);

            this.Resize += BetterListView_Resize;
        }

        void BetterListView_Resize(object sender, EventArgs e)
        {
            if (_b) Invalidate();
        }

        public void setMessage(string s){
            message = s;
        }

        protected override void OnNotifyMessage(Message m)
        {
            //Filter out the WM_ERASEBKGND message
            if (m.Msg != 0x14)
            {
                base.OnNotifyMessage(m);
            }
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == 20)
            {
                if (this.Items.Count == 0)
                {
                    _b = true;
                    Graphics g = this.CreateGraphics();
                    int w = (this.Width - g.MeasureString(message,
                      this.Font).ToSize().Width) / 2;
                    g.DrawString(message, this.Font,
                      SystemBrushes.ControlText, w, 30);
                }
            }

            if (m.Msg == 4127) this.Invalidate();
        }
    }
}
