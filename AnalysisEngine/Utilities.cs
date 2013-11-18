using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AnalysisEngine
{
    class Utilities
    {
        public static string GetCmdArguments(Process p)
        {
            string toret = "";
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + p.Id))
                {
                    foreach (ManagementObject obj in s.Get())
                    {
                        toret += obj["CommandLine"];
                    }
                }
                return toret;
            }
            catch (Exception) { return ""; }
        }
        #region Memory Scanner
        static byte[] metxor = new byte[] { 0x8C, 0x8B, 0x9B, 0x9E, 0x8F, 0x96, 0xA0, 0x8C, 0x86, 0x8C, 0xA0, 0x8F, 0x8D, 0x90, 0x9C, 0x9A, 0x8C, 0x8C, 0xA0, 0x98, 0x9A, 0x8B, 0x8F, 0x96, 0x9B };
        static byte[] javameter = new byte[] { 0x92, 0x9a, 0x8B, 0x9E, 0x8C, 0x8F, 0x93, 0x90, 0x96, 0x8B };

        [StructLayout(LayoutKind.Sequential)]
        public struct ParentProcessUtilities
        {
            // These members must match PROCESS_BASIC_INFORMATION
            internal IntPtr Reserved1;
            internal IntPtr PebBaseAddress;
            internal IntPtr Reserved2_0;
            internal IntPtr Reserved2_1;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;

            [DllImport("ntdll.dll")]
            private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);
            public static Process GetParentProcess()
            {
                return GetParentProcess(Process.GetCurrentProcess().Handle);
            }

            public static Process GetParentProcess(int id)
            {
                Process process = Process.GetProcessById(id);
                return GetParentProcess(process.Handle);
            }
            public static Process GetParentProcess(IntPtr handle)
            {
                ParentProcessUtilities pbi = new ParentProcessUtilities();
                int returnLength;
                int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
                if (status != 0)
                    throw new Win32Exception(status);

                try
                {
                    return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
                }
                catch (ArgumentException)
                {
                    // not found
                    return null;
                }
            }
        }

        public static bool scanProcess(Process p)
        {
            p.Refresh();
            try
            {
                if (p.HasExited)
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            //Console.WriteLine("Scanning " + p.ProcessName);
            IntPtr Addy = new IntPtr();
            List<MEMORY_BASIC_INFORMATION> MemReg = new List<MEMORY_BASIC_INFORMATION>();
            while (true)
            {
                MEMORY_BASIC_INFORMATION MemInfo = new MEMORY_BASIC_INFORMATION();
                int MemDump = VirtualQueryEx(p.Handle, Addy, out  MemInfo, Marshal.SizeOf(MemInfo));
                if (MemDump == 0) break;
                if (0 != (MemInfo.State & MEM_COMMIT) && 0 != (MemInfo.Protect & WRITABLE) && 0 == (MemInfo.Protect & PAGE_GUARD))
                {
                    MemReg.Add(MemInfo);
                }
                Addy = new IntPtr(MemInfo.BaseAddress.ToInt64() + MemInfo.RegionSize.ToInt64());
            }

            for (int i = 0; i < MemReg.Count; i++)
            {
                byte[] buff = new byte[MemReg[i].RegionSize.ToInt32()];
                ReadProcessMemory(p.Handle, MemReg[i].BaseAddress, buff, MemReg[i].RegionSize.ToInt32(), IntPtr.Zero);

                for (int j = 0; j < buff.Length; j++)
                {
                    buff[j] = (byte)(buff[j] ^ 0xFF);
                }

                long Result = IndexOf(buff, metxor);
                if (Result > 0)
                {
                    buff = null;
                    GC.Collect();
                    return true;
                }

                Result = IndexOf(buff, javameter);
                if (Result > 0)
                {
                    buff = null;
                    GC.Collect();
                    return true;
                }
                buff = null;
            }
            GC.Collect();
            return false;
        }

        public static bool scanJava(Process p)
        {
            p.Refresh();
            try
            {
                if (p.HasExited)
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            //Console.WriteLine("Scanning " + p.ProcessName);
            IntPtr Addy = new IntPtr();
            List<MEMORY_BASIC_INFORMATION> MemReg = new List<MEMORY_BASIC_INFORMATION>();
            while (true)
            {
                MEMORY_BASIC_INFORMATION MemInfo = new MEMORY_BASIC_INFORMATION();
                int MemDump = VirtualQueryEx(p.Handle, Addy, out  MemInfo, Marshal.SizeOf(MemInfo));
                if (MemDump == 0) break;
                if (0 != (MemInfo.State & MEM_COMMIT) && 0 != (MemInfo.Protect & WRITABLE) && 0 == (MemInfo.Protect & PAGE_GUARD))
                {
                    MemReg.Add(MemInfo);
                }
                Addy = new IntPtr(MemInfo.BaseAddress.ToInt64() + MemInfo.RegionSize.ToInt64());
            }

            for (int i = 0; i < MemReg.Count; i++)
            {
                byte[] buff = new byte[MemReg[i].RegionSize.ToInt32()];
                ReadProcessMemory(p.Handle, MemReg[i].BaseAddress, buff, MemReg[i].RegionSize.ToInt32(), IntPtr.Zero);

                long Result = IndexOf(buff, javameter);
                if (Result > 0)
                {
                    buff = null;
                    GC.Collect();
                    return true;
                }
                buff = null;
            }
            GC.Collect();
            return false;
        }

        public static unsafe long IndexOf(byte[] Haystack, byte[] Needle)
        {
            fixed (byte* H = Haystack) fixed (byte* N = Needle)
            {
                long i = 0;
                for (byte* hNext = H, hEnd = H + Haystack.LongLength; hNext < hEnd; i++, hNext++)
                {
                    bool Found = true;
                    for (byte* hInc = hNext, nInc = N, nEnd = N + Needle.LongLength; Found && nInc < nEnd; Found = *nInc == *hInc, nInc++, hInc++) ;
                    if (Found) return i;
                }
                return -1;
            }
        }

        #endregion

        #region pinvoke imports
        private const int PAGE_READWRITE = 0x04;
        private const int PAGE_WRITECOPY = 0x08;
        private const int PAGE_EXECUTE_READWRITE = 0x40;
        private const int PAGE_EXECUTE_WRITECOPY = 0x80;
        private const int PAGE_GUARD = 0x100;
        private const int WRITABLE = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_GUARD;
        private const int MEM_COMMIT = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
          IntPtr hProcess,
          IntPtr lpBaseAddress,
          [Out] byte[] lpBuffer,
          int dwSize,
          IntPtr lpNumberOfBytesRead
         );

        [DllImport("kernel32.dll")]
        internal static extern Int32 VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        protected static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("winmm.dll")]
        internal static extern uint timeBeginPeriod(uint period);
        [DllImport("winmm.dll")]
        internal static extern uint timeEndPeriod(uint period);


        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        #endregion
    }
}
