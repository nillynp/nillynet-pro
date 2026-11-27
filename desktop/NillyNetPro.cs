// ============================================================================
// NillyNet Pro v1.3.3 — Ultra-Light Native Windows 10/11 Network Monitor,
//                     Full Wi-Fi Band/Channel/Speed Analyzer, Wi-Fi Passwords & DNS
// created by Nilly graphics (Nillygraphics · Sotiris Christos) — https://nillygraphics.com/
// Strictly C# 5 compatible (.NET Framework 4.x csc.exe — 0 external DLLs)
// Features:
//  - <45ms launch · ~6-10 MB trimmed RAM · 0 MB RAM / 0% CPU when closed
//  - 100% Responsive Columns & Header (zero white header tail at any window width)
//  - Tab 1: Live 60s Download/Upload Sparkline + Native Win32 iphlpapi TCP/UDP per process
//  - Tab 2: Full On-Demand Wi-Fi Analyzer (SSID, BSSID, Band 2.4/5/6 GHz, Channel,
//           Wi-Fi Standard 4/5/6/6E/7, Live Rx/Tx Mbps, Signal % & dBm bar, Security/Cipher,
//           Nearby Wi-Fi Networks & Channels Scanner + Saved Wi-Fi Password 1-click Copy)
//           + Full Ethernet/Adapter Dashboard when on LAN
//  - Tab 3: Multi-Host Ping (1.1.1.1 / 8.8.8.8 / Custom) + Flush DNS + 1-Click DNS
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("NillyNet Pro")]
[assembly: AssemblyDescription("Ultra-Light Native Network Monitor, Full Wi-Fi Band/Speed/Channel Analyzer, Wi-Fi Passwords & DNS Tools — created by Nilly graphics (Nillygraphics · Sotiris Christos)")]
[assembly: AssemblyCompany("Nilly graphics (Nillygraphics · Sotiris Christos) — https://nillygraphics.com/")]
[assembly: AssemblyProduct("NillyNet Pro")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Nilly graphics (Sotiris Christos) — https://nillygraphics.com/")]
[assembly: AssemblyTrademark("Nilly graphics / Nillygraphics — Sotiris Christos")]
[assembly: AssemblyVersion("1.3.4.0")]
[assembly: AssemblyFileVersion("1.3.4.0")]

namespace NillyNetPro
{
    internal static class Native
    {
        public const int AF_INET = 2;
        public const int TCP_TABLE_OWNER_PID_ALL = 5;
        public const int UDP_TABLE_OWNER_PID = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public int owningPid;
        }

        [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr minSize, IntPtr maxSize);
        [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int sz);
        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] private static extern int SetWindowTheme(IntPtr hWnd, string app, string id);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
        [DllImport("user32.dll", CharSet = CharSet.Auto)] private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr CreateIconFromResourceEx(byte[] presbits, uint dwResSize, bool fIcon, uint dwVer, int cx, int cy, uint Flags);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

        public static void TrimMemory()
        {
            try
            {
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Optimized, false);
                SetProcessWorkingSetSize(GetCurrentProcess(), (IntPtr)(-1), (IntPtr)(-1));
            }
            catch { }
        }

        public static void SetDarkTitlebar(IntPtr hwnd, bool dark)
        {
            if (hwnd == IntPtr.Zero) return;
            try
            {
                int v = dark ? 1 : 0;
                if (DwmSetWindowAttribute(hwnd, 20, ref v, 4) != 0)
                    DwmSetWindowAttribute(hwnd, 19, ref v, 4);
            }
            catch { }
        }

        public static void SetDarkScrollbars(Control c, bool dark)
        {
            if (c == null || !c.IsHandleCreated) return;
            try { SetWindowTheme(c.Handle, dark ? "DarkMode_Explorer" : "Explorer", null); } catch { }
        }

        public static void SetCue(TextBox tb, string text)
        {
            if (tb == null || !tb.IsHandleCreated) return;
            try { SendMessage(tb.Handle, 0x1501, (IntPtr)1, text); } catch { }
        }

        public static Bitmap LoadCrispIcon(string icoPath, int sz)
        {
            if (string.IsNullOrEmpty(icoPath) || !File.Exists(icoPath)) return null;
            try
            {
                byte[] data = File.ReadAllBytes(icoPath);
                if (data.Length < 22) return null;
                int cnt = BitConverter.ToUInt16(data, 4), bestIdx = 0, bestW = 0;
                for (int i = 0; i < cnt; i++)
                {
                    int off = 6 + i * 16;
                    if (off + 16 > data.Length) break;
                    int w = data[off]; if (w == 0) w = 256;
                    if (w > bestW) { bestW = w; bestIdx = i; }
                }
                int eOff = 6 + bestIdx * 16;
                int len = BitConverter.ToInt32(data, eOff + 8);
                int imgOff = BitConverter.ToInt32(data, eOff + 12);
                Bitmap dst = new Bitmap(sz, sz, PixelFormat.Format32bppArgb);
                using (Graphics g = Graphics.FromImage(dst))
                {
                    g.SmoothingMode = SmoothingMode.HighQuality;
                    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    g.Clear(Color.Transparent);
                    if (imgOff + 4 < data.Length && data[imgOff] == 0x89 && data[imgOff + 1] == 0x50)
                        using (MemoryStream ms = new MemoryStream(data, imgOff, len))
                        using (Image img = Image.FromStream(ms))
                            g.DrawImage(img, 0, 0, sz, sz);
                }
                return dst;
            }
            catch { return null; }
        }

        public static void ApplyTaskbarIcon(Form f, string icoPath)
        {
            if (f == null || !f.IsHandleCreated || !File.Exists(icoPath)) return;
            try
            {
                byte[] data = File.ReadAllBytes(icoPath);
                IntPtr hBig = MakeHIcon(data, 48), hSm = MakeHIcon(data, 16);
                if (hBig != IntPtr.Zero) SendMessage(f.Handle, 0x0080, (IntPtr)1, hBig);
                if (hSm != IntPtr.Zero) SendMessage(f.Handle, 0x0080, (IntPtr)0, hSm);
            }
            catch { }
        }

        private static IntPtr MakeHIcon(byte[] data, int desired)
        {
            if (data.Length < 22) return IntPtr.Zero;
            int cnt = BitConverter.ToUInt16(data, 4), bestIdx = 0, bestDiff = int.MaxValue;
            for (int i = 0; i < cnt; i++)
            {
                int off = 6 + i * 16;
                if (off + 16 > data.Length) break;
                int w = data[off]; if (w == 0) w = 256;
                int d = Math.Abs(w - desired);
                if (w >= desired && d < bestDiff) { bestDiff = d; bestIdx = i; }
                else if (bestDiff == int.MaxValue && d < bestDiff) { bestDiff = d; bestIdx = i; }
            }
            int eOff = 6 + bestIdx * 16;
            int len = BitConverter.ToInt32(data, eOff + 8);
            int imgOff = BitConverter.ToInt32(data, eOff + 12);
            if (len <= 0 || imgOff + len > data.Length) return IntPtr.Zero;
            byte[] slice = new byte[len]; Buffer.BlockCopy(data, imgOff, slice, 0, len);
            return CreateIconFromResourceEx(slice, (uint)len, true, 0x00030000, desired, desired, 0);
        }
    }

    internal sealed class DoubleBufferedLV : ListView
    {
        public DoubleBufferedLV()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
            UpdateStyles();
        }
    }

    internal sealed class DoubleBufferedPanel : Panel
    {
        public DoubleBufferedPanel()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint, true);
            UpdateStyles();
        }
    }

    internal sealed class NetConn
    {
        public string Proto, ProcessName, LocalEnd, RemoteEnd, State, Norm;
        public int Pid;
    }

    internal sealed class WifiLiveInfo
    {
        public bool HasWifi;
        public bool Connected;
        public string AdapterName = "";
        public string Description = "";
        public string MacAddress = "";
        public string State = "";
        public string Ssid = "";
        public string Bssid = "";
        public string RadioType = "";
        public string WifiGen = "";
        public string Band = "";
        public string Channel = "";
        public string RxMbps = "";
        public string TxMbps = "";
        public int SignalPct = -1;
        public int EstDbm = -100;
        public string Auth = "";
        public string Cipher = "";
        public string IpV4 = "";
        public string Gateway = "";
        public string Dns = "";
        public string FallbackNote = "";
    }

    internal sealed class NearbyWifi
    {
        public string Ssid = "";
        public string Bssid = "";
        public string Band = "";
        public string Channel = "";
        public int SignalPct = 0;
        public int EstDbm = -100;
        public string Radio = "";
        public string Auth = "";
    }

    internal static class NetEngine
    {
        private static readonly string[] TcpStates = new string[]
        {
            "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
            "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
        };

        public static string FmtRate(double bytesPerSec)
        {
            if (bytesPerSec < 1024) return bytesPerSec.ToString("0") + " B/s";
            double kb = bytesPerSec / 1024.0;
            if (kb < 1024) return kb.ToString("0.0") + " KB/s";
            return (kb / 1024.0).ToString("0.00") + " MB/s";
        }

        public static string FmtBytes(long b)
        {
            if (b < 1024) return b + " B";
            double d = b / 1024.0;
            if (d < 1024) return d.ToString("0.0") + " KB";
            d /= 1024.0;
            if (d < 1024) return d.ToString("0.0") + " MB";
            return (d / 1024.0).ToString("0.00") + " GB";
        }

        public static int SignalPctToDbm(int pct)
        {
            if (pct <= 0) return -100;
            if (pct >= 100) return -50;
            return (pct / 2) - 100;
        }

        public static string DetectBand(string bandHint, string channelStr, string radio)
        {
            if (!string.IsNullOrEmpty(bandHint))
            {
                if (bandHint.IndexOf("6", StringComparison.OrdinalIgnoreCase) >= 0) return "6 GHz";
                if (bandHint.IndexOf("5", StringComparison.OrdinalIgnoreCase) >= 0) return "5 GHz";
                if (bandHint.IndexOf("2.4", StringComparison.OrdinalIgnoreCase) >= 0 || bandHint.IndexOf("2,4", StringComparison.OrdinalIgnoreCase) >= 0) return "2.4 GHz";
            }
            int ch;
            if (int.TryParse((channelStr ?? "").Trim(), out ch))
            {
                if (ch >= 1 && ch <= 14) return "2.4 GHz";
                if (ch >= 32 && ch <= 177) return "5 GHz";
                if (ch > 177) return "6 GHz";
            }
            if (!string.IsNullOrEmpty(radio))
            {
                if (radio.IndexOf("802.11ac", StringComparison.OrdinalIgnoreCase) >= 0 || radio.IndexOf("802.11a", StringComparison.OrdinalIgnoreCase) >= 0) return "5 GHz";
                if (radio.IndexOf("802.11b", StringComparison.OrdinalIgnoreCase) >= 0 || radio.IndexOf("802.11g", StringComparison.OrdinalIgnoreCase) >= 0) return "2.4 GHz";
            }
            return "—";
        }

        public static string FormatWifiGen(string radio)
        {
            if (string.IsNullOrEmpty(radio)) return "—";
            string r = radio.ToLowerInvariant();
            if (r.Contains("802.11be")) return "Wi-Fi 7 (802.11be)";
            if (r.Contains("802.11ax")) return "Wi-Fi 6/6E (802.11ax)";
            if (r.Contains("802.11ac")) return "Wi-Fi 5 (802.11ac)";
            if (r.Contains("802.11n")) return "Wi-Fi 4 (802.11n)";
            if (r.Contains("802.11g")) return "Wi-Fi 3 (802.11g)";
            if (r.Contains("802.11a")) return "802.11a";
            if (r.Contains("802.11b")) return "802.11b";
            return radio.Trim();
        }

        public static void GetTotalBytes(out long rx, out long tx)
        {
            rx = 0; tx = 0;
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                for (int i = 0; i < nics.Length; i++)
                {
                    NetworkInterface n = nics[i];
                    if (n.OperationalStatus != OperationalStatus.Up) continue;
                    if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback || n.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                    IPv4InterfaceStatistics st = n.GetIPv4Statistics();
                    rx += st.BytesReceived;
                    tx += st.BytesSent;
                }
            }
            catch { }
        }

        public static List<NetConn> GetActiveConnections()
        {
            List<NetConn> list = new List<NetConn>(128);
            Dictionary<int, string> pidNames = new Dictionary<int, string>();
            Process[] procs = Process.GetProcesses();
            for (int i = 0; i < procs.Length; i++)
            {
                try { pidNames[procs[i].Id] = procs[i].ProcessName; } catch { }
                finally { try { procs[i].Dispose(); } catch { } }
            }
            ReadTcp(list, pidNames);
            ReadUdp(list, pidNames);
            list.Sort(delegate(NetConn a, NetConn b)
            {
                bool aEst = (a.State == "ESTABLISHED"), bEst = (b.State == "ESTABLISHED");
                if (aEst != bEst) return aEst ? -1 : 1;
                return StringComparer.OrdinalIgnoreCase.Compare(a.ProcessName, b.ProcessName);
            });
            return list;
        }

        private static int DecodePort(byte[] p) { return (p == null || p.Length < 2) ? 0 : ((p[0] << 8) | p[1]); }
        private static string DecodeIp(uint addr) { return new IPAddress(addr).ToString(); }

        private static void ReadTcp(List<NetConn> list, Dictionary<int, string> pidNames)
        {
            int size = 0;
            Native.GetExtendedTcpTable(IntPtr.Zero, ref size, true, Native.AF_INET, Native.TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (Native.GetExtendedTcpTable(buf, ref size, true, Native.AF_INET, Native.TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
                int count = Marshal.ReadInt32(buf);
                IntPtr rowPtr = new IntPtr(buf.ToInt64() + 4);
                int rowSize = Marshal.SizeOf(typeof(Native.MIB_TCPROW_OWNER_PID));
                for (int i = 0; i < count; i++)
                {
                    Native.MIB_TCPROW_OWNER_PID row = (Native.MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(Native.MIB_TCPROW_OWNER_PID));
                    rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);
                    string pName;
                    if (!pidNames.TryGetValue(row.owningPid, out pName)) pName = row.owningPid == 0 ? "System Idle" : ("PID " + row.owningPid);
                    string st = (row.state < TcpStates.Length) ? TcpStates[row.state] : row.state.ToString();
                    string rem = (row.state == 2) ? "*:*" : (DecodeIp(row.remoteAddr) + ":" + DecodePort(row.remotePort));
                    NetConn c = new NetConn
                    {
                        Proto = "TCP", ProcessName = pName, Pid = row.owningPid,
                        LocalEnd = DecodeIp(row.localAddr) + ":" + DecodePort(row.localPort), RemoteEnd = rem, State = st
                    };
                    c.Norm = (c.ProcessName + " " + c.Pid + " " + c.LocalEnd + " " + c.RemoteEnd + " " + c.State + " tcp").ToLowerInvariant();
                    list.Add(c);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static void ReadUdp(List<NetConn> list, Dictionary<int, string> pidNames)
        {
            int size = 0;
            Native.GetExtendedUdpTable(IntPtr.Zero, ref size, true, Native.AF_INET, Native.UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) return;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (Native.GetExtendedUdpTable(buf, ref size, true, Native.AF_INET, Native.UDP_TABLE_OWNER_PID, 0) != 0) return;
                int count = Marshal.ReadInt32(buf);
                IntPtr rowPtr = new IntPtr(buf.ToInt64() + 4);
                int rowSize = Marshal.SizeOf(typeof(Native.MIB_UDPROW_OWNER_PID));
                for (int i = 0; i < count; i++)
                {
                    Native.MIB_UDPROW_OWNER_PID row = (Native.MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(Native.MIB_UDPROW_OWNER_PID));
                    rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);
                    string pName;
                    if (!pidNames.TryGetValue(row.owningPid, out pName)) pName = row.owningPid == 0 ? "System" : ("PID " + row.owningPid);
                    NetConn c = new NetConn
                    {
                        Proto = "UDP", ProcessName = pName, Pid = row.owningPid,
                        LocalEnd = DecodeIp(row.localAddr) + ":" + DecodePort(row.localPort), RemoteEnd = "*:*", State = "OPEN"
                    };
                    c.Norm = (c.ProcessName + " " + c.Pid + " " + c.LocalEnd + " udp").ToLowerInvariant();
                    list.Add(c);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static string RunNetsh(string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh.exe", args)
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, StandardOutputEncoding = Encoding.UTF8
                };
                using (Process p = Process.Start(psi))
                {
                    string txt = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    return txt;
                }
            }
            catch { return ""; }
        }

        private static string ValAfterColon(string line)
        {
            int idx = line.IndexOf(':');
            return (idx >= 0 && idx + 1 < line.Length) ? line.Substring(idx + 1).Trim() : "";
        }

        public static WifiLiveInfo GetLiveWifiInfo()
        {
            WifiLiveInfo info = new WifiLiveInfo();
            // Fill active adapter IP / Gateway / DNS / MAC cleanly via .NET NetworkInterface
            try
            {
                NetworkInterface activeNic = null;
                foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (n.OperationalStatus != OperationalStatus.Up) continue;
                    if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback || n.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                    if (n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) { activeNic = n; break; }
                    if (activeNic == null) activeNic = n;
                }
                if (activeNic != null)
                {
                    info.AdapterName = activeNic.Name;
                    info.Description = activeNic.Description;
                    byte[] mac = activeNic.GetPhysicalAddress().GetAddressBytes();
                    if (mac.Length == 6)
                        info.MacAddress = string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    IPInterfaceProperties ip = activeNic.GetIPProperties();
                    foreach (UnicastIPAddressInformation u in ip.UnicastAddresses)
                        if (u.Address.AddressFamily == AddressFamily.InterNetwork) { info.IpV4 = u.Address.ToString(); break; }
                    foreach (GatewayIPAddressInformation g in ip.GatewayAddresses)
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork) { info.Gateway = g.Address.ToString(); break; }
                    List<string> dnsList = new List<string>();
                    foreach (IPAddress d in ip.DnsAddresses)
                        if (d.AddressFamily == AddressFamily.InterNetwork) dnsList.Add(d.ToString());
                    info.Dns = string.Join(", ", dnsList.ToArray());
                    if (activeNic.Speed > 0)
                    {
                        string sp = (activeNic.Speed / 1000000.0).ToString("0") + " Mbps";
                        info.RxMbps = sp; info.TxMbps = sp;
                    }
                }
            }
            catch { }

            string raw = RunNetsh("wlan show interfaces");
            if (string.IsNullOrEmpty(raw) || raw.IndexOf("wlansvc", StringComparison.OrdinalIgnoreCase) >= 0 || raw.IndexOf("There is no wireless", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                info.HasWifi = false;
                info.FallbackNote = "Ενεργή σύνδεση Ethernet / LAN (η υπηρεσία Wi-Fi δεν είναι ενεργή σε αυτό το PC — σε laptop με Wi-Fi εμφανίζονται αυτόματα Band 2.4/5/6 GHz, Κανάλι, Rx/Tx Mbps, Σήμα dBm & Κοντινά Δίκτυα).";
                return info;
            }

            string bandHint = "";
            string[] lines = raw.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < lines.Length; i++)
            {
                string ln = lines[i].Trim();
                int c = ln.IndexOf(':');
                if (c <= 0) continue;
                string k = ln.Substring(0, c).Trim().ToLowerInvariant();
                string v = ln.Substring(c + 1).Trim();
                if (k == "name" || k == "όνομα") { info.HasWifi = true; info.AdapterName = v; }
                else if (k == "description" || k == "περιγραφή") info.Description = v;
                else if (k == "state" || k == "κατάσταση") { info.State = v; info.Connected = (v.IndexOf("connected", StringComparison.OrdinalIgnoreCase) >= 0 && v.IndexOf("dis", StringComparison.OrdinalIgnoreCase) < 0) || v.IndexOf("συνδεδεμ", StringComparison.OrdinalIgnoreCase) >= 0; }
                else if (k == "ssid") info.Ssid = v;
                else if (k == "bssid" || k == "ap bssid") info.Bssid = v;
                else if (k == "radio type" || k.Contains("τύπος ραδιο")) { info.RadioType = v; info.WifiGen = FormatWifiGen(v); }
                else if (k == "band" || k == "ζώνη") bandHint = v;
                else if (k == "channel" || k == "κανάλι") info.Channel = v;
                else if (k.Contains("receive rate") || k.Contains("ρυθμός λήψ")) info.RxMbps = v + (v.IndexOf("Mbps", StringComparison.OrdinalIgnoreCase) < 0 ? " Mbps" : "");
                else if (k.Contains("transmit rate") || k.Contains("ρυθμός μετάδ")) info.TxMbps = v + (v.IndexOf("Mbps", StringComparison.OrdinalIgnoreCase) < 0 ? " Mbps" : "");
                else if (k == "authentication" || k.Contains("έλεγχος ταυτότ")) info.Auth = v;
                else if (k == "cipher" || k.Contains("κρυπτογρ")) info.Cipher = v;
                else if (k == "signal" || k == "σήμα")
                {
                    Match m = Regex.Match(v, @"(\d+)");
                    if (m.Success)
                    {
                        int pct;
                        if (int.TryParse(m.Groups[1].Value, out pct)) { info.SignalPct = pct; info.EstDbm = SignalPctToDbm(pct); }
                    }
                }
            }
            info.Band = DetectBand(bandHint, info.Channel, info.RadioType);
            if (string.IsNullOrEmpty(info.WifiGen)) info.WifiGen = FormatWifiGen(info.RadioType);
            return info;
        }

        public static List<NearbyWifi> ScanNearbyWifiNetworks()
        {
            List<NearbyWifi> list = new List<NearbyWifi>();
            string raw = RunNetsh("wlan show networks mode=bssid");
            if (string.IsNullOrEmpty(raw) || raw.IndexOf("wlansvc", StringComparison.OrdinalIgnoreCase) >= 0) return list;

            string[] lines = raw.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            string curSsid = "", curAuth = "";
            NearbyWifi curBss = null;
            for (int i = 0; i < lines.Length; i++)
            {
                string ln = lines[i].Trim();
                int c = ln.IndexOf(':');
                if (c <= 0) continue;
                string k = ln.Substring(0, c).Trim().ToLowerInvariant();
                string v = ln.Substring(c + 1).Trim();

                if (k.StartsWith("ssid "))
                {
                    curSsid = string.IsNullOrEmpty(v) ? "(Κρυφό Wi-Fi)" : v;
                    curAuth = ""; curBss = null;
                }
                else if (k == "authentication" || k.Contains("έλεγχος ταυτότ")) curAuth = v;
                else if (k.StartsWith("bssid "))
                {
                    curBss = new NearbyWifi { Ssid = curSsid, Bssid = v, Auth = curAuth };
                    list.Add(curBss);
                }
                else if (curBss != null)
                {
                    if (k == "signal" || k == "σήμα")
                    {
                        Match m = Regex.Match(v, @"(\d+)");
                        int pct;
                        if (m.Success && int.TryParse(m.Groups[1].Value, out pct)) { curBss.SignalPct = pct; curBss.EstDbm = SignalPctToDbm(pct); }
                    }
                    else if (k == "radio type" || k.Contains("τύπος ραδιο")) curBss.Radio = FormatWifiGen(v);
                    else if (k == "band" || k == "ζώνη") curBss.Band = DetectBand(v, curBss.Channel, curBss.Radio);
                    else if (k == "channel" || k == "κανάλι")
                    {
                        curBss.Channel = v;
                        if (string.IsNullOrEmpty(curBss.Band) || curBss.Band == "—")
                            curBss.Band = DetectBand("", v, curBss.Radio);
                    }
                }
            }
            list.Sort(delegate(NearbyWifi a, NearbyWifi b) { return b.SignalPct.CompareTo(a.SignalPct); });
            return list;
        }

        public static List<string> GetSavedWifiProfiles()
        {
            List<string> profiles = new List<string>();
            string raw = RunNetsh("wlan show profiles");
            string[] lines = raw.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < lines.Length; i++)
            {
                int col = lines[i].IndexOf(':');
                if (col > 0 && (lines[i].IndexOf("Profile", StringComparison.OrdinalIgnoreCase) >= 0 || lines[i].IndexOf("Προφίλ", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    string name = lines[i].Substring(col + 1).Trim();
                    if (name.Length > 0 && !profiles.Contains(name)) profiles.Add(name);
                }
            }
            return profiles;
        }

        public static string GetWifiPassword(string profile)
        {
            if (string.IsNullOrEmpty(profile)) return "";
            string raw = RunNetsh("wlan show profile name=\"" + profile.Replace("\"", "") + "\" key=clear");
            string[] lines = raw.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].IndexOf("Key Content", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    lines[i].IndexOf("Περιεχόμενο κλειδιού", StringComparison.OrdinalIgnoreCase) >= 0)
                    return ValAfterColon(lines[i]);
            }
            return "(Δεν υπάρχει αποθηκευμένος κωδικός ή ανοιχτό δίκτυο)";
        }
    }

    internal sealed class MainForm : Form
    {
        private bool _dark = true;
        private int _activeTab = 0;
        private bool _paused = false;
        private readonly ToolTip _tip = new ToolTip();
        private Color _bgMain, _bgPanel, _bgSurf, _bgHover, _bgSel, _bgAlt, _border, _fgMain, _fgMuted, _accent, _cyan, _green, _pink;

        private readonly Panel _header, _tabBar, _statusBar;
        private readonly PictureBox _logoBox;
        private readonly Label _lblTitle, _lblSub, _lblStatus, _lblLiveRate;
        private readonly TextBox _txtSearch;
        private readonly AkButton _btnTabLive, _btnTabWifi, _btnTabTools, _btnPause, _btnTheme, _btnInfo;
        private readonly LinkLabel _lnkBrand;

        // Tab 0: Live sparkline + TCP/UDP table
        private readonly Panel _pnlLive;
        private readonly DoubleBufferedPanel _graphPanel;
        private readonly DoubleBufferedLV _lvConns;
        private readonly double[] _rxHist = new double[60];
        private readonly double[] _txHist = new double[60];
        private long _prevRx, _prevTx, _startRx, _startTx;
        private DateTime _prevSample = DateTime.UtcNow;
        private double _curRxRate, _curTxRate;
        private List<NetConn> _allConns = new List<NetConn>();
        private int _connSortCol = 0; private bool _connSortAsc = true;
        private int _nearSortCol = 3; private bool _nearSortAsc = false;
        private static readonly string[] ConnCols = new string[] { "Εφαρμογή (Process)", "PID", "Proto", "Τοπική Διεύθυνση", "Απομακρυσμένη IP:Port", "Κατάσταση" };
        private static readonly string[] NearCols = new string[] { "Όνομα Wi-Fi (SSID)", "Band", "Κανάλι", "Σήμα / dBm", "Πρότυπο Wi-Fi", "Ασφάλεια", "BSSID (MAC)" };

        // Tab 1: Full Wi-Fi Analyzer + Nearby Networks + Adapters + Saved Passwords
        private readonly Panel _pnlWifi;
        private readonly DoubleBufferedPanel _wifiCard;
        private readonly SplitContainer _wifiSplit, _botSplit;
        private readonly AkButton _btnScanWifi, _btnCopyWifi;
        private readonly DoubleBufferedLV _lvNearby, _lvAdapters;
        private readonly ListBox _lstWifi;
        private readonly Label _lblWifiKey;
        private WifiLiveInfo _liveWifi = new WifiLiveInfo();
        private List<NearbyWifi> _nearbyWifi = new List<NearbyWifi>();
        private string _lastRevealedKey = "";

        // Tab 2: Ping & DNS Tools
        private readonly Panel _pnlTools;
        private readonly FlowLayoutPanel _toolRow;
        private readonly TextBox _txtPingHost, _txtToolLog;
        private readonly AkButton _btnPingAll, _btnFlushDns, _btnDnsCf, _btnDnsGgl, _btnDnsAuto, _btnWinNet, _btnNetNote;

        private readonly System.Windows.Forms.Timer _timer;
        private bool _wasMinimized = false;
        private Bitmap _logoBmp;
        private readonly Font _fTitle = new Font("Segoe UI", 10.5f, FontStyle.Bold);
        private readonly Font _fWifiHdr = new Font("Segoe UI", 11.2f, FontStyle.Bold);
        private readonly Font _fUi = new Font("Segoe UI", 9.0f);
        private readonly Font _fBold = new Font("Segoe UI", 9.0f, FontStyle.Bold);
        private readonly Font _fSmall = new Font("Segoe UI", 8.2f);

        public int ConnectionsCount { get { return _allConns.Count; } }

        public MainForm(bool smokeMode) : this(smokeMode, null) { }

        public MainForm(bool smokeMode, string initialFilter)
        {
            _dark = ReadSuiteDark(true);
            Text = "NillyNet Pro — Ultra-Light Network Monitor, Wi-Fi Band/Speed Analyzer & DNS | Nilly graphics";
            Size = new Size(1120, 700);
            MinimumSize = new Size(680, 480);
            StartPosition = FormStartPosition.CenterScreen;

            string icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NillyNetPro.ico");
            if (File.Exists(icoPath))
            {
                _logoBmp = Native.LoadCrispIcon(icoPath, 26);
                try { Icon = new Icon(icoPath); } catch { }
            }

            // Responsive Ariakit Header
            _header = new Panel { Dock = DockStyle.Top, Height = 52 };
            _logoBox = new PictureBox { Size = new Size(26, 26), Location = new Point(12, 12), SizeMode = PictureBoxSizeMode.Zoom, Image = _logoBmp };
            _lblTitle = new Label { Text = "NillyNet Pro", AutoSize = true, Location = new Point(44, 6), Font = _fTitle, UseMnemonic = false };
            _lblSub = new Label { Text = "Ultra-Light Network · Wi-Fi Band/Speed · 0 MB Idle RAM", AutoSize = true, Location = new Point(45, 27), Font = new Font("Segoe UI", 7.6f), UseMnemonic = false };
            _header.Paint += delegate(object s, PaintEventArgs pe)
            {
                using (Pen p = new Pen(_border)) pe.Graphics.DrawLine(p, 0, _header.Height - 1, _header.Width, _header.Height - 1);
            };

            _txtSearch = new TextBox { Width = 200, Height = 26, BorderStyle = BorderStyle.FixedSingle, Font = _fUi };
            if (!string.IsNullOrEmpty(initialFilter)) _txtSearch.Text = initialFilter;
            _txtSearch.TextChanged += delegate { RenderConnections(); };
            _txtSearch.HandleCreated += delegate { Native.SetCue(_txtSearch, "Φίλτρο process / IP (Ctrl+F)..."); };
            _btnPause = MkBtn("", 34, AkKind.Secondary, AkIcon.Pause, "Παύση / Συνέχεια ανανέωσης (Space)", delegate { _paused = !_paused; _btnPause.Icon = _paused ? AkIcon.Play : AkIcon.Pause; _btnPause.Active = _paused; _btnPause.Invalidate(); });
            _btnTheme = MkBtn("", 32, AkKind.Secondary, AkIcon.Sun, "Αλλαγή Dark / Light θέματος", delegate { _dark = !_dark; ApplyTheme(); });
            _btnInfo = MkBtn("", 32, AkKind.AccentOutline, AkIcon.Info, "Ultra-Light Specs & Πληροφορίες", delegate { ShowInfoDialog(); });
            _header.Controls.AddRange(new Control[] { _logoBox, _lblTitle, _lblSub, _txtSearch, _btnPause, _btnTheme, _btnInfo });
            _header.Resize += delegate { LayoutHeader(); _header.Invalidate(); };

            // Responsive Ariakit Bottom-Indicator Tab Bar
            _tabBar = new Panel { Dock = DockStyle.Top, Height = 38 };
            _tabBar.Paint += delegate(object s, PaintEventArgs pe)
            {
                using (Pen p = new Pen(_border)) pe.Graphics.DrawLine(p, 0, _tabBar.Height - 1, _tabBar.Width, _tabBar.Height - 1);
            };
            _btnTabLive = MkBtn("Ζωντανή Κίνηση & Διεργασίες", 206, AkKind.Tab, AkIcon.None, "Live Download/Upload + TCP/UDP ανά εφαρμογή", delegate { SwitchTab(0); });
            _btnTabWifi = MkBtn("Wi-Fi Analyzer & Κωδικοί", 186, AkKind.Tab, AkIcon.None, "Band 2.4/5/6 GHz, Κανάλι, Rx/Tx Mbps, Σήμα dBm, Κοντινά Δίκτυα & Κωδικοί", delegate { SwitchTab(1); });
            _btnTabTools = MkBtn("Ping & 1-Κλικ DNS", 148, AkKind.Tab, AkIcon.None, "Έλεγχος Ping, Flush DNS & Cloudflare/Google DNS", delegate { SwitchTab(2); });
            _lblLiveRate = new Label { AutoSize = true, Font = _fBold, TextAlign = ContentAlignment.MiddleRight, UseMnemonic = false };
            _tabBar.Controls.AddRange(new Control[] { _btnTabLive, _btnTabWifi, _btnTabTools, _lblLiveRate });
            _tabBar.Resize += delegate { LayoutTabBar(); _tabBar.Invalidate(); };

            // ---- Tab 0: Live Traffic & TCP/UDP ----
            _pnlLive = new Panel { Dock = DockStyle.Fill };
            _graphPanel = new DoubleBufferedPanel { Dock = DockStyle.Top, Height = 122 };
            _graphPanel.Paint += GraphPanel_Paint;
            _lvConns = BuildLV(ConnCols, new int[] { 220, 68, 58, 200, 260, 140 });
            SetSortHeaders(_lvConns, ConnCols, _connSortCol, _connSortAsc);
            _lvConns.ColumnClick += delegate(object s, ColumnClickEventArgs e)
            {
                if (_connSortCol == e.Column) _connSortAsc = !_connSortAsc;
                else { _connSortCol = e.Column; _connSortAsc = true; }
                SetSortHeaders(_lvConns, ConnCols, _connSortCol, _connSortAsc);
                RenderConnections();
            };
            _lvConns.Resize += delegate { FitConnColumns(); };
            ContextMenuStrip ctx = new ContextMenuStrip();
            ctx.Items.Add("Αντιγραφή Απομακρυσμένης IP", null, delegate { if (_lvConns.SelectedItems.Count > 0) try { Clipboard.SetText(_lvConns.SelectedItems[0].SubItems[4].Text); } catch { } });
            ctx.Items.Add("Δες Διεργασία στο NillyTask Pro", null, delegate
            {
                string taskExe = FindSiblingExe("NillyTaskPro", "NillyTaskPro.exe");
                if (taskExe != null)
                {
                    string proc = (_lvConns.SelectedItems.Count > 0) ? _lvConns.SelectedItems[0].SubItems[0].Text : "";
                    if (proc.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) proc = proc.Substring(0, proc.Length - 4);
                    string arg = !string.IsNullOrEmpty(proc) ? ("--filter \"" + proc.Replace("\"", "") + "\"") : "";
                    try { Process.Start(new ProcessStartInfo(taskExe, arg) { WorkingDirectory = Path.GetDirectoryName(taskExe), UseShellExecute = true }); } catch { }
                }
            });
            ctx.Items.Add("Τερματισμός Διεργασίας", null, delegate { KillSelectedConnProcess(); });
            _lvConns.ContextMenuStrip = ctx;
            _pnlLive.Controls.Add(_lvConns);
            _pnlLive.Controls.Add(_graphPanel);

            // ---- Tab 1: Full Wi-Fi Band/Speed Analyzer + Nearby + Adapters + Passwords ----
            _pnlWifi = new Panel { Dock = DockStyle.Fill, Visible = false, Padding = new Padding(10) };

            _wifiCard = new DoubleBufferedPanel { Dock = DockStyle.Top, Height = 128 };
            _wifiCard.Paint += WifiCard_Paint;
            _btnScanWifi = MkBtn("Σάρωση Wi-Fi", 132, AkKind.Primary, AkIcon.Refresh, "Επανασάρωση Wi-Fi Band, Σήματος & Κοντινών Δικτύων (On-Demand · 0% idle)", delegate { RefreshWifiTabAsync(); });
            _btnScanWifi.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _wifiCard.Controls.Add(_btnScanWifi);
            _wifiCard.Resize += delegate { _btnScanWifi.Location = new Point(Math.Max(10, _wifiCard.Width - _btnScanWifi.Width - 12), 10); _wifiCard.Invalidate(); };

            _wifiSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterWidth = 5 };

            // Top split: Nearby Wi-Fi Networks (Band, Channel, Signal dBm, Standard)
            Panel pNear = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 6, 0, 0) };
            Label lblNear = new Label { Text = "ΚΟΝΤΙΝΑ ΔΙΚΤΥΑ WI-FI & ΚΑΝΑΛΙΑ (Band 2.4 / 5 / 6 GHz · Σήμα dBm · Πρότυπο)", Dock = DockStyle.Top, Height = 22, Font = _fBold, UseMnemonic = false };
            _lvNearby = BuildLV(NearCols, new int[] { 220, 72, 64, 120, 155, 130, 145 });
            SetSortHeaders(_lvNearby, NearCols, _nearSortCol, _nearSortAsc);
            _lvNearby.ColumnClick += delegate(object s, ColumnClickEventArgs e)
            {
                if (_nearSortCol == e.Column) _nearSortAsc = !_nearSortAsc;
                else { _nearSortCol = e.Column; _nearSortAsc = (e.Column != 3); }
                SetSortHeaders(_lvNearby, NearCols, _nearSortCol, _nearSortAsc);
                RenderNearbyWifi();
            };
            _lvNearby.Resize += delegate { FitLastColumn(_lvNearby, new int[] { 200, 72, 62, 120, 155, 130, 140 }); };
            pNear.Controls.Add(_lvNearby);
            pNear.Controls.Add(lblNear);
            _wifiSplit.Panel1.Controls.Add(pNear);

            // Bottom split: Left = Adapters Table (58%), Right = Saved Wi-Fi Passwords (42%)
            _botSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterWidth = 5 };
            Panel pAdap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 4, 0, 0) };
            Label lblAdap = new Label { Text = "ΠΡΟΣΑΡΜΟΓΕΙΣ ΔΙΚΤΥΟΥ (LAN / WI-FI)", Dock = DockStyle.Top, Height = 22, Font = _fBold, UseMnemonic = false };
            _lvAdapters = BuildLV(new string[] { "Προσαρμογέας", "Τύπος", "Ταχύτητα", "IPv4", "Gateway", "DNS" },
                                  new int[] { 135, 85, 82, 110, 105, 120 });
            _lvAdapters.Resize += delegate { FitLastColumn(_lvAdapters, new int[] { 110, 70, 72, 95, 95, 110 }); };
            pAdap.Controls.Add(_lvAdapters);
            pAdap.Controls.Add(lblAdap);
            _botSplit.Panel1.Controls.Add(pAdap);

            Panel pPass = new Panel { Dock = DockStyle.Fill, Padding = new Padding(6, 4, 0, 0) };
            Label lblW = new Label { Text = "ΑΠΟΘΗΚΕΥΜΕΝΑ WI-FI (ΚΛΙΚ ΓΙΑ ΚΩΔΙΚΟ)", Dock = DockStyle.Top, Height = 22, Font = _fBold, UseMnemonic = false };
            _lstWifi = new ListBox { Dock = DockStyle.Left, Width = 160, BorderStyle = BorderStyle.FixedSingle, Font = _fSmall };
            _lstWifi.SelectedIndexChanged += delegate
            {
                if (_lstWifi.SelectedItem != null)
                {
                    string prof = _lstWifi.SelectedItem.ToString();
                    _lastRevealedKey = NetEngine.GetWifiPassword(prof);
                    _lblWifiKey.Text = prof + "\n\nΚωδικός:\n" + _lastRevealedKey;
                }
            };
            Panel keyRight = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10, 2, 4, 4) };
            _lblWifiKey = new Label { Dock = DockStyle.Top, Height = 76, Font = _fBold, UseMnemonic = false, Text = "Επίλεξε ένα Wi-Fi για εμφάνιση κωδικού." };
            _btnCopyWifi = MkBtn("Αντιγραφή Κωδικού", 160, AkKind.Primary, AkIcon.Copy, "Αντιγραφή κωδικού Wi-Fi στο πρόχειρο", delegate
            {
                if (!string.IsNullOrEmpty(_lastRevealedKey) && !_lastRevealedKey.StartsWith("("))
                {
                    try
                    {
                        Clipboard.SetText(_lastRevealedKey);
                        _lblStatus.Text = "✓ Αντιγράφηκε ο κωδικός Wi-Fi στο πρόχειρο.";
                    }
                    catch { _lblStatus.Text = "⚠ Το πρόχειρο είναι απασχολημένο. Δοκίμασε ξανά."; }
                }
            });
            _btnCopyWifi.Location = new Point(10, 84);
            keyRight.Controls.Add(_btnCopyWifi);
            keyRight.Controls.Add(_lblWifiKey);
            pPass.Controls.Add(keyRight);
            pPass.Controls.Add(_lstWifi);
            pPass.Controls.Add(lblW);
            _botSplit.Panel2.Controls.Add(pPass);

            _wifiSplit.Panel2.Controls.Add(_botSplit);
            _pnlWifi.Controls.Add(_wifiSplit);
            _pnlWifi.Controls.Add(_wifiCard);
            _pnlWifi.Resize += delegate { LayoutWifiSplits(); };

            // ---- Tab 2: Responsive Ping & DNS Tools ----
            _pnlTools = new Panel { Dock = DockStyle.Fill, Visible = false, Padding = new Padding(12) };
            _toolRow = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(0, 0, 0, 8) };
            _txtPingHost = new TextBox { Width = 160, Height = 26, Text = "1.1.1.1", BorderStyle = BorderStyle.FixedSingle, Font = _fUi, Margin = new Padding(0, 3, 6, 4) };
            _btnPingAll = MkBtn("Ping Test (CF/Google/Host)", 206, AkKind.Primary, AkIcon.Play, "Μέτρηση ms σε 1.1.1.1, 8.8.8.8 & custom host", delegate { RunPingAsync(); });
            _btnFlushDns = MkBtn("Flush DNS", 104, AkKind.Secondary, AkIcon.Refresh, "Καθαρισμός DNS cache", delegate { RunFlushDns(); });
            _btnDnsCf = MkBtn("DNS 1.1.1.1 (Cloudflare)", 170, AkKind.Secondary, AkIcon.None, "Cloudflare γρήγορο DNS", delegate { ApplyDns("1.1.1.1", "1.0.0.1"); });
            _btnDnsGgl = MkBtn("DNS 8.8.8.8 (Google)", 150, AkKind.Secondary, AkIcon.None, "Google DNS", delegate { ApplyDns("8.8.8.8", "8.8.4.4"); });
            _btnDnsAuto = MkBtn("Αυτόματο DNS", 118, AkKind.Secondary, AkIcon.None, "Επαναφορά DHCP DNS", delegate { ApplyDns(null, null); });
            _btnWinNet = MkBtn("Ρυθμίσεις Win", 114, AkKind.Secondary, AkIcon.External, "Άνοιγμα Windows Network Settings", delegate { OpenUrl("ms-settings:network"); });
            _btnNetNote = MkBtn("Αναφορά σε NillyNote", 172, AkKind.AccentOutline, AkIcon.External, "Αποστολή πλήρους αναφοράς Δικτύου/Wi-Fi/Ping σε NillyNote Pro", delegate { SendReportToNillyNote(); });
            _toolRow.Controls.AddRange(new Control[] { _txtPingHost, _btnPingAll, _btnFlushDns, _btnDnsCf, _btnDnsGgl, _btnDnsAuto, _btnWinNet, _btnNetNote });

            _txtToolLog = new TextBox
            {
                Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 9.5f),
                Text = "Έτοιμο για δοκιμή Ping, Flush DNS ή γρήγορη αλλαγή DNS (1.1.1.1 / 8.8.8.8).\r\n"
            };
            _pnlTools.Controls.Add(_txtToolLog);
            _pnlTools.Controls.Add(_toolRow);

            Panel body = new Panel { Dock = DockStyle.Fill };
            body.Controls.AddRange(new Control[] { _pnlLive, _pnlWifi, _pnlTools });

            // Status bar
            _statusBar = new Panel { Dock = DockStyle.Bottom, Height = 28, Padding = new Padding(12, 0, 12, 0) };
            _statusBar.Paint += delegate(object s, PaintEventArgs pe)
            {
                using (Pen p = new Pen(_border)) pe.Graphics.DrawLine(p, 0, 0, _statusBar.Width, 0);
            };
            _lblStatus = new Label { Dock = DockStyle.Fill, Font = _fSmall, TextAlign = ContentAlignment.MiddleLeft, UseMnemonic = false, AutoEllipsis = true };
            _lnkBrand = new LinkLabel
            {
                Text = "created by Nilly graphics (Sotiris Christos) — nillygraphics.com",
                Dock = DockStyle.Right, AutoSize = true, Font = _fSmall, Padding = new Padding(8, 5, 2, 0), LinkBehavior = LinkBehavior.HoverUnderline
            };
            _lnkBrand.LinkClicked += delegate { OpenUrl("https://nillygraphics.com/"); };
            _statusBar.Controls.Add(_lblStatus);
            _statusBar.Controls.Add(_lnkBrand);

            Controls.Add(body);
            Controls.Add(_tabBar);
            Controls.Add(_header);
            Controls.Add(_statusBar);

            NetEngine.GetTotalBytes(out _startRx, out _startTx);
            _prevRx = _startRx; _prevTx = _startTx; _prevSample = DateTime.UtcNow;

            _timer = new System.Windows.Forms.Timer { Interval = 1500 };
            _timer.Tick += delegate { if (!_paused && WindowState != FormWindowState.Minimized) SampleNetwork(); };

            Resize += delegate
            {
                if (WindowState == FormWindowState.Minimized) _wasMinimized = true;
                else if (_wasMinimized)
                {
                    _wasMinimized = false;
                    long rrx, rtx;
                    NetEngine.GetTotalBytes(out rrx, out rtx);
                    _prevRx = rrx; _prevTx = rtx; _prevSample = DateTime.UtcNow;
                    if (!_paused) SampleNetwork();
                }
            };

            HandleCreated += delegate
            {
                Native.SetDarkTitlebar(Handle, _dark);
                Native.ApplyTaskbarIcon(this, icoPath);
            };
            Shown += delegate
            {
                LayoutHeader();
                LayoutTabBar();
                FitConnColumns();
                Native.TrimMemory();
            };

            ApplyTheme();
            LayoutHeader();
            LayoutTabBar();
            SampleNetwork();
            if (!smokeMode) _timer.Start();
        }

        private AkButton MkBtn(string txt, int w, AkKind kind, AkIcon icon, string tip, EventHandler click)
        {
            AkButton b = new AkButton
            {
                Kind = kind, Icon = icon,
                Text = txt, Width = w, Height = 28, Font = _fBold,
                Margin = new Padding(0, 0, 6, 4)
            };
            b.Click += click;
            _tip.SetToolTip(b, tip);
            return b;
        }

        private DoubleBufferedLV BuildLV(string[] cols, int[] widths)
        {
            DoubleBufferedLV lv = new DoubleBufferedLV
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false,
                BorderStyle = BorderStyle.None, OwnerDraw = true, Font = _fUi, HideSelection = false
            };
            for (int i = 0; i < cols.Length; i++) lv.Columns.Add(cols[i], widths[i], HorizontalAlignment.Left);
            lv.DrawColumnHeader += DrawHdr;
            lv.DrawSubItem += DrawSub;
            lv.HandleCreated += delegate { Native.SetDarkScrollbars(lv, _dark); };
            return lv;
        }

        private void LayoutHeader()
        {
            int w = Math.Max(580, _header.ClientSize.Width);
            int pad = 12, gap = 6;
            if (_lblSub != null) _lblSub.Visible = (w >= 760);
            if (_lnkBrand != null) _lnkBrand.Visible = (w >= 760);
            int rx = w - pad;
            rx -= _btnInfo.Width; _btnInfo.Location = new Point(rx, 11); rx -= gap;
            rx -= _btnTheme.Width; _btnTheme.Location = new Point(rx, 11); rx -= gap;
            rx -= _btnPause.Width; _btnPause.Location = new Point(rx, 11); rx -= gap;
            int brandRight = _lblSub.Visible ? Math.Max(_lblTitle.Right, _lblSub.Right) + 16 : (_lblTitle.Right + 16);
            int availSearch = rx - brandRight;
            if (availSearch >= 150)
            {
                if (_header.Height != 50) _header.Height = 50;
                int sw = Math.Min(230, availSearch);
                _txtSearch.SetBounds(rx - sw, 12, sw, 26);
            }
            else
            {
                if (_header.Height != 84) _header.Height = 84;
                _txtSearch.SetBounds(pad, 50, Math.Max(140, w - pad * 2), 26);
            }
        }

        private void LayoutTabBar()
        {
            int w = Math.Max(560, _tabBar.ClientSize.Width);
            int x = 10;
            _btnTabLive.Location = new Point(x, 5); x += _btnTabLive.Width + 6;
            _btnTabWifi.Location = new Point(x, 5); x += _btnTabWifi.Width + 6;
            _btnTabTools.Location = new Point(x, 5); x += _btnTabTools.Width + 6;
            if (w >= x + 175)
            {
                if (_tabBar.Height != 38) _tabBar.Height = 38;
                _lblLiveRate.Location = new Point(w - Math.Max(160, _lblLiveRate.Width) - 12, 10);
            }
            else
            {
                if (_tabBar.Height != 62) _tabBar.Height = 62;
                _lblLiveRate.Location = new Point(12, 38);
            }
        }

        private void FitConnColumns()
        {
            FitLastColumn(_lvConns, new int[] { 200, 66, 56, 185, 225, 130 });
        }

        // Proportionally fills 100% of ListView ClientSize.Width — ZERO white header gap!
        private static void FitLastColumn(ListView lv, int[] mins)
        {
            if (lv == null || lv.Columns.Count != mins.Length) return;
            int cw = lv.ClientSize.Width;
            if (cw <= 120) return;
            int totalMin = 0;
            for (int i = 0; i < mins.Length; i++) totalMin += mins[i];
            int target = Math.Max(totalMin, cw - 2);
            int used = 0;
            for (int i = 0; i < mins.Length - 1; i++)
            {
                int w = (int)Math.Round((double)mins[i] * target / totalMin);
                lv.Columns[i].Width = Math.Max(46, w);
                used += lv.Columns[i].Width;
            }
            lv.Columns[mins.Length - 1].Width = Math.Max(75, target - used);
        }

        private void ApplyTheme()
        {
            if (_dark)
            {
                _bgMain = Color.FromArgb(29, 31, 32); _bgPanel = Color.FromArgb(34, 36, 38);
                _bgSurf = Color.FromArgb(39, 41, 43); _bgHover = Color.FromArgb(48, 51, 54);
                _bgSel = Color.FromArgb(56, 46, 34); _bgAlt = Color.FromArgb(26, 28, 29);
                _border = Color.FromArgb(54, 57, 61); _fgMain = Color.FromArgb(242, 244, 247);
                _fgMuted = Color.FromArgb(154, 160, 168); _accent = Color.FromArgb(252, 150, 31);
                _cyan = Color.FromArgb(102, 217, 239); _green = Color.FromArgb(166, 226, 46);
                _pink = Color.FromArgb(240, 104, 118);
            }
            else
            {
                _bgMain = Color.FromArgb(248, 249, 250); _bgPanel = Color.White;
                _bgSurf = Color.White; _bgHover = Color.FromArgb(236, 239, 243);
                _bgSel = Color.FromArgb(254, 238, 218); _bgAlt = Color.FromArgb(244, 246, 249);
                _border = Color.FromArgb(214, 220, 228); _fgMain = Color.FromArgb(26, 29, 33);
                _fgMuted = Color.FromArgb(95, 104, 116); _accent = Color.FromArgb(224, 118, 12);
                _cyan = Color.FromArgb(14, 132, 168); _green = Color.FromArgb(62, 145, 32);
                _pink = Color.FromArgb(196, 40, 56);
            }

            Color well = _dark ? Color.FromArgb(24, 26, 27) : Color.White;
            Native.SetDarkTitlebar(Handle, _dark);
            BackColor = _bgMain; ForeColor = _fgMain;
            _header.BackColor = _bgPanel; _tabBar.BackColor = _bgPanel; _statusBar.BackColor = _bgPanel;
            _pnlLive.BackColor = _bgMain; _pnlWifi.BackColor = _bgMain; _pnlTools.BackColor = _bgMain;
            _graphPanel.BackColor = _bgPanel; _wifiCard.BackColor = _bgPanel;
            _lblTitle.ForeColor = _fgMain; _lblSub.ForeColor = _fgMuted; _lblStatus.ForeColor = _fgMuted; _lblLiveRate.ForeColor = _accent;
            _lnkBrand.LinkColor = _fgMuted; _lnkBrand.ActiveLinkColor = _accent;
            _txtSearch.BackColor = well; _txtSearch.ForeColor = _fgMain;
            _txtPingHost.BackColor = well; _txtPingHost.ForeColor = _fgMain;
            _txtToolLog.BackColor = well; _txtToolLog.ForeColor = _fgMain;
            _lstWifi.BackColor = well; _lstWifi.ForeColor = _fgMain;
            _lblWifiKey.ForeColor = _accent;

            DoubleBufferedLV[] lvs = new DoubleBufferedLV[] { _lvConns, _lvNearby, _lvAdapters };
            for (int i = 0; i < lvs.Length; i++)
            {
                lvs[i].BackColor = well; lvs[i].ForeColor = _fgMain;
                Native.SetDarkScrollbars(lvs[i], _dark); lvs[i].Invalidate();
            }
            _header.Invalidate(); _tabBar.Invalidate(); _statusBar.Invalidate();
            _graphPanel.Invalidate();
            _wifiCard.Invalidate();
            StyleButtons();
        }

        private void StyleButtons()
        {
            _btnTheme.Icon = _dark ? AkIcon.Sun : AkIcon.Moon;
            _btnPause.Icon = _paused ? AkIcon.Play : AkIcon.Pause;
            _btnPause.Active = _paused;
            _btnTabLive.Active = (_activeTab == 0);
            _btnTabWifi.Active = (_activeTab == 1);
            _btnTabTools.Active = (_activeTab == 2);
            AkButton[] all = new AkButton[]
            {
                _btnPause, _btnTheme, _btnInfo, _btnTabLive, _btnTabWifi, _btnTabTools,
                _btnScanWifi, _btnCopyWifi, _btnPingAll, _btnFlushDns, _btnDnsCf, _btnDnsGgl, _btnDnsAuto, _btnWinNet, _btnNetNote
            };
            for (int i = 0; i < all.Length; i++) { all[i].Dark = _dark; all[i].Invalidate(); }
        }

        public void SwitchTab(int tab)
        {
            _activeTab = tab;
            _pnlLive.Visible = (tab == 0);
            _pnlWifi.Visible = (tab == 1);
            _pnlTools.Visible = (tab == 2);
            StyleButtons();
            if (tab == 0) FitConnColumns();
            if (tab == 1) { LayoutWifiSplits(); RefreshWifiTabAsync(); }
        }

        private void LayoutWifiSplits()
        {
            try
            {
                if (_wifiSplit != null && _wifiSplit.Height > 220)
                    _wifiSplit.SplitterDistance = Math.Max(120, Math.Min(_wifiSplit.Height - 155, (int)(_wifiSplit.Height * 0.46)));
                if (_botSplit != null && _botSplit.Width > 420)
                {
                    int leftW = Math.Max(260, Math.Min(_botSplit.Width - 360, (int)(_botSplit.Width * 0.56)));
                    _botSplit.SplitterDistance = leftW;
                    int rightW = Math.Max(180, _botSplit.Width - leftW - 14);
                    _lstWifi.Width = Math.Max(110, Math.Min(165, rightW / 2 - 12));
                }
            }
            catch { }
        }

        public void RefreshWifiSyncForSmoke()
        {
            _liveWifi = NetEngine.GetLiveWifiInfo();
            _nearbyWifi = NetEngine.ScanNearbyWifiNetworks();
            PopulateWifiTabUi(NetEngine.GetSavedWifiProfiles());
        }

        private void RefreshWifiTabAsync()
        {
            _btnScanWifi.Enabled = false;
            _lblStatus.Text = "Σάρωση Wi-Fi (Band 2.4/5/6 GHz, Κανάλια, Rx/Tx Mbps, Σήμα dBm)...";
            Thread th = new Thread(delegate()
            {
                WifiLiveInfo live = NetEngine.GetLiveWifiInfo();
                List<NearbyWifi> near = NetEngine.ScanNearbyWifiNetworks();
                List<string> profs = NetEngine.GetSavedWifiProfiles();
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        _liveWifi = live;
                        _nearbyWifi = near;
                        PopulateWifiTabUi(profs);
                        _btnScanWifi.Enabled = true;
                        Native.TrimMemory();
                    });
                }
                catch { }
            });
            th.IsBackground = true; th.Start();
        }

        private static void SetSortHeaders(ListView lv, string[] cols, int sortCol, bool asc)
        {
            if (lv == null || lv.Columns.Count < cols.Length) return;
            for (int i = 0; i < cols.Length; i++)
                lv.Columns[i].Text = cols[i] + (i == sortCol ? (asc ? " ▲" : " ▼") : "");
        }

        private void RenderNearbyWifi()
        {
            List<NearbyWifi> sorted = new List<NearbyWifi>(_nearbyWifi);
            int sign = _nearSortAsc ? 1 : -1;
            sorted.Sort(delegate(NearbyWifi a, NearbyWifi b)
            {
                int cmp = 0;
                if (_nearSortCol == 1) cmp = string.Compare(a.Band ?? "", b.Band ?? "", StringComparison.OrdinalIgnoreCase);
                else if (_nearSortCol == 2)
                {
                    int ca, cb;
                    if (int.TryParse(a.Channel, out ca) && int.TryParse(b.Channel, out cb)) cmp = ca.CompareTo(cb);
                    else cmp = string.Compare(a.Channel ?? "", b.Channel ?? "", StringComparison.OrdinalIgnoreCase);
                }
                else if (_nearSortCol == 3) cmp = a.SignalPct.CompareTo(b.SignalPct);
                else if (_nearSortCol == 4) cmp = string.Compare(a.Radio ?? "", b.Radio ?? "", StringComparison.OrdinalIgnoreCase);
                else if (_nearSortCol == 5) cmp = string.Compare(a.Auth ?? "", b.Auth ?? "", StringComparison.OrdinalIgnoreCase);
                else if (_nearSortCol == 6) cmp = string.Compare(a.Bssid ?? "", b.Bssid ?? "", StringComparison.OrdinalIgnoreCase);
                else cmp = string.Compare(a.Ssid ?? "", b.Ssid ?? "", StringComparison.OrdinalIgnoreCase);
                if (cmp == 0) cmp = b.SignalPct.CompareTo(a.SignalPct);
                return sign * cmp;
            });
            _lvNearby.BeginUpdate();
            _lvNearby.Items.Clear();
            for (int i = 0; i < sorted.Count; i++)
            {
                NearbyWifi n = sorted[i];
                ListViewItem it = new ListViewItem(n.Ssid);
                it.SubItems.Add(n.Band);
                it.SubItems.Add(string.IsNullOrEmpty(n.Channel) ? "—" : ("Ch " + n.Channel));
                it.SubItems.Add(string.Format("{0}% ({1} dBm)", n.SignalPct, n.EstDbm));
                it.SubItems.Add(string.IsNullOrEmpty(n.Radio) ? "—" : n.Radio);
                it.SubItems.Add(string.IsNullOrEmpty(n.Auth) ? "—" : n.Auth);
                it.SubItems.Add(n.Bssid);
                _lvNearby.Items.Add(it);
            }
            _lvNearby.EndUpdate();
            FitLastColumn(_lvNearby, new int[] { 200, 72, 62, 120, 155, 130, 140 });
        }

        private void PopulateWifiTabUi(List<string> profs)
        {
            _wifiCard.Invalidate();
            RenderNearbyWifi();

            // Adapters table
            _lvAdapters.BeginUpdate();
            _lvAdapters.Items.Clear();
            try
            {
                foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    IPInterfaceProperties ip = n.GetIPProperties();
                    string ipv4 = "", gw = "", dns = "";
                    foreach (UnicastIPAddressInformation u in ip.UnicastAddresses)
                        if (u.Address.AddressFamily == AddressFamily.InterNetwork) { ipv4 = u.Address.ToString(); break; }
                    foreach (GatewayIPAddressInformation g in ip.GatewayAddresses)
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork) { gw = g.Address.ToString(); break; }
                    List<string> dnsList = new List<string>();
                    foreach (IPAddress d in ip.DnsAddresses)
                        if (d.AddressFamily == AddressFamily.InterNetwork) dnsList.Add(d.ToString());
                    dns = string.Join(", ", dnsList.ToArray());
                    string spd = n.Speed > 0 ? ((n.Speed / 1000000.0).ToString("0") + " Mbps") : "—";

                    ListViewItem it = new ListViewItem(n.Name);
                    it.SubItems.Add(n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? "Wi-Fi" : n.NetworkInterfaceType.ToString());
                    it.SubItems.Add(spd);
                    it.SubItems.Add(ipv4);
                    it.SubItems.Add(gw);
                    it.SubItems.Add(dns);
                    _lvAdapters.Items.Add(it);
                }
            }
            catch { }
            _lvAdapters.EndUpdate();
            FitLastColumn(_lvAdapters, new int[] { 125, 80, 78, 105, 100, 115 });

            _lstWifi.Items.Clear();
            if (profs != null)
                for (int i = 0; i < profs.Count; i++) _lstWifi.Items.Add(profs[i]);

            _lblStatus.Text = _liveWifi.HasWifi
                ? string.Format("✓ Wi-Fi: {0} ({1} · Ch {2} · {3}% / {4} dBm) · Κοντινά δίκτυα: {5}", _liveWifi.Ssid, _liveWifi.Band, _liveWifi.Channel, _liveWifi.SignalPct, _liveWifi.EstDbm, _nearbyWifi.Count)
                : string.Format("✓ Ενεργός Προσαρμογέας: {0} ({1} · {2}) · On-demand Wi-Fi scan (0% idle CPU)", _liveWifi.AdapterName, _liveWifi.RxMbps, _liveWifi.IpV4);
        }

        private void WifiCard_Paint(object sender, PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            int w = _wifiCard.Width, h = _wifiCard.Height;
            using (SolidBrush br = new SolidBrush(_bgPanel)) g.FillRectangle(br, 0, 0, w, h);
            using (Pen bp = new Pen(_border)) g.DrawRectangle(bp, 0, 0, w - 1, h - 1);

            WifiLiveInfo wf = _liveWifi ?? new WifiLiveInfo();
            int rightLimit = Math.Max(220, w - 160);

            if (wf.HasWifi && wf.Connected)
            {
                TextRenderer.DrawText(g, string.Format("{0}   ·   {1}   ·   {2}", wf.Ssid, wf.Band, wf.WifiGen),
                    _fWifiHdr, new Rectangle(14, 10, rightLimit - 14, 24), _fgMain, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

                string line2 = string.Format("Ταχύτητα Link: ↓ {0}  /  ↑ {1}    ·    Κανάλι: {2}    ·    Ασφάλεια: {3} ({4})",
                    wf.RxMbps, wf.TxMbps, wf.Channel, wf.Auth, wf.Cipher);
                TextRenderer.DrawText(g, line2, _fBold, new Rectangle(14, 40, w - 28, 20), _cyan, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

                string line3 = string.Format("Router BSSID: {0}    ·    IPv4: {1}    ·    Gateway: {2}    ·    DNS: {3}",
                    wf.Bssid, wf.IpV4, wf.Gateway, wf.Dns);
                TextRenderer.DrawText(g, line3, _fSmall, new Rectangle(14, 64, w - 28, 18), _fgMuted, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

                // Visual Signal Quality Bar
                int pct = Math.Max(0, Math.Min(100, wf.SignalPct));
                Color sigCol = pct >= 70 ? _green : (pct >= 45 ? _accent : _pink);
                string qual = pct >= 75 ? "Εξαιρετικό" : (pct >= 50 ? "Καλό" : "Αδύναμο");
                TextRenderer.DrawText(g, string.Format("Σήμα Wi-Fi: {0}% ({1} dBm · {2})", pct, wf.EstDbm, qual),
                    _fBold, new Rectangle(14, 92, 260, 20), sigCol, TextFormatFlags.Left | TextFormatFlags.NoPrefix);

                Rectangle barBg = new Rectangle(278, 96, Math.Max(80, w - 300), 12);
                using (SolidBrush bBg = new SolidBrush(_bgMain)) g.FillRectangle(bBg, barBg);
                int fw = (int)Math.Round(barBg.Width * (pct / 100.0));
                if (fw > 0) using (SolidBrush bFill = new SolidBrush(sigCol)) g.FillRectangle(bFill, barBg.X, barBg.Y, fw, barBg.Height);
                using (Pen bPen = new Pen(_border)) g.DrawRectangle(bPen, barBg);
            }
            else
            {
                string hdr = string.IsNullOrEmpty(wf.AdapterName)
                    ? "Δίκτυο & Wi-Fi Analyzer"
                    : string.Format("Ενεργή Σύνδεση: {0}  ({1})  ·  Link: {2}", wf.AdapterName, wf.Description, string.IsNullOrEmpty(wf.RxMbps) ? "—" : wf.RxMbps);
                TextRenderer.DrawText(g, hdr, _fTitle,
                    new Rectangle(14, 12, rightLimit - 14, 24), _fgMain, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

                string netLine = string.Format("IPv4: {0}    ·    Gateway: {1}    ·    DNS: {2}    ·    MAC: {3}",
                    string.IsNullOrEmpty(wf.IpV4) ? "—" : wf.IpV4,
                    string.IsNullOrEmpty(wf.Gateway) ? "—" : wf.Gateway,
                    string.IsNullOrEmpty(wf.Dns) ? "—" : wf.Dns,
                    string.IsNullOrEmpty(wf.MacAddress) ? "—" : wf.MacAddress);
                TextRenderer.DrawText(g, netLine, _fBold, new Rectangle(14, 42, w - 28, 20), _cyan, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

                string note = !string.IsNullOrEmpty(wf.FallbackNote)
                    ? wf.FallbackNote
                    : "Δεν υπάρχει συνδεδεμένο Wi-Fi αυτή τη στιγμή. Πάτα «↻ Σάρωση Wi-Fi» για ανανέωση Band (2.4/5/6 GHz), Καναλιού & Ταχυτήτων.";
                TextRenderer.DrawText(g, note, _fSmall, new Rectangle(14, 70, w - 28, 46), _fgMuted, TextFormatFlags.Left | TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix);
            }
        }

        public void SampleNetwork()
        {
            long rx, tx;
            NetEngine.GetTotalBytes(out rx, out tx);
            DateTime now = DateTime.UtcNow;
            double dt = Math.Max(0.2, (now - _prevSample).TotalSeconds);
            _curRxRate = Math.Max(0, (rx - _prevRx) / dt);
            _curTxRate = Math.Max(0, (tx - _prevTx) / dt);
            _prevRx = rx; _prevTx = tx; _prevSample = now;

            Array.Copy(_rxHist, 1, _rxHist, 0, _rxHist.Length - 1);
            Array.Copy(_txHist, 1, _txHist, 0, _txHist.Length - 1);
            _rxHist[_rxHist.Length - 1] = _curRxRate;
            _txHist[_txHist.Length - 1] = _curTxRate;
            _graphPanel.Invalidate();

            _lblLiveRate.Text = string.Format("↓ {0}   ↑ {1}", NetEngine.FmtRate(_curRxRate), NetEngine.FmtRate(_curTxRate));
            LayoutTabBar();

            if (_activeTab == 0)
            {
                _allConns = NetEngine.GetActiveConnections();
                RenderConnections();
                int est = 0; for (int i = 0; i < _allConns.Count; i++) if (_allConns[i].State == "ESTABLISHED") est++;
                _lblStatus.Text = string.Format("Ενεργές συνδέσεις: {0} ESTABLISHED / {1} σύνολο  ·  Συνεδρία: ↓ {2} / ↑ {3}",
                    est, _allConns.Count, NetEngine.FmtBytes(Math.Max(0, rx - _startRx)), NetEngine.FmtBytes(Math.Max(0, tx - _startTx)));
            }
        }

        private void RenderConnections()
        {
            string q = _txtSearch.Text.Trim().ToLowerInvariant();
            List<NetConn> rows = new List<NetConn>(_allConns.Count);
            for (int i = 0; i < _allConns.Count; i++)
            {
                NetConn c = _allConns[i];
                if (q.Length == 0 || c.Norm.IndexOf(q, StringComparison.Ordinal) >= 0) rows.Add(c);
            }
            int sign = _connSortAsc ? 1 : -1;
            rows.Sort(delegate(NetConn a, NetConn b)
            {
                int cmp = 0;
                if (_connSortCol == 1) cmp = a.Pid.CompareTo(b.Pid);
                else if (_connSortCol == 2) cmp = string.Compare(a.Proto ?? "", b.Proto ?? "", StringComparison.OrdinalIgnoreCase);
                else if (_connSortCol == 3) cmp = string.Compare(a.LocalEnd ?? "", b.LocalEnd ?? "", StringComparison.OrdinalIgnoreCase);
                else if (_connSortCol == 4) cmp = string.Compare(a.RemoteEnd ?? "", b.RemoteEnd ?? "", StringComparison.OrdinalIgnoreCase);
                else if (_connSortCol == 5) cmp = string.Compare(a.State ?? "", b.State ?? "", StringComparison.OrdinalIgnoreCase);
                else cmp = string.Compare(a.ProcessName ?? "", b.ProcessName ?? "", StringComparison.OrdinalIgnoreCase);
                if (cmp == 0) cmp = a.Pid.CompareTo(b.Pid);
                return sign * cmp;
            });
            _lvConns.BeginUpdate();
            _lvConns.Items.Clear();
            int max = Math.Min(350, rows.Count);
            for (int i = 0; i < max; i++)
            {
                NetConn c = rows[i];
                ListViewItem it = new ListViewItem(c.ProcessName);
                it.SubItems.Add(c.Pid.ToString());
                it.SubItems.Add(c.Proto);
                it.SubItems.Add(c.LocalEnd);
                it.SubItems.Add(c.RemoteEnd);
                it.SubItems.Add(c.State);
                it.Tag = c;
                _lvConns.Items.Add(it);
            }
            _lvConns.EndUpdate();
        }

        private void GraphPanel_Paint(object sender, PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            int w = _graphPanel.Width, h = _graphPanel.Height;
            using (SolidBrush br = new SolidBrush(_bgPanel)) g.FillRectangle(br, 0, 0, w, h);
            using (Pen bp = new Pen(_border)) g.DrawLine(bp, 0, h - 1, w, h - 1);

            Rectangle chart = new Rectangle(12, 26, Math.Max(40, w - 24), Math.Max(24, h - 36));
            using (SolidBrush brC = new SolidBrush(_bgMain)) g.FillRectangle(brC, chart);
            using (Pen gridP = new Pen(_border))
            {
                g.DrawRectangle(gridP, chart);
                g.DrawLine(gridP, chart.Left, chart.Top + chart.Height / 2, chart.Right, chart.Top + chart.Height / 2);
            }

            double peak = 16384;
            for (int i = 0; i < _rxHist.Length; i++)
            {
                if (_rxHist[i] > peak) peak = _rxHist[i];
                if (_txHist[i] > peak) peak = _txHist[i];
            }
            DrawSeries(g, chart, _rxHist, peak, _cyan);
            DrawSeries(g, chart, _txHist, peak, _green);

            TextRenderer.DrawText(g, string.Format("ΖΩΝΤΑΝΗ ΚΙΝΗΣΗ ΔΙΚΤΥΟΥ (60s)   —   ↓ Λήψη: {0}   |   ↑ Αποστολή: {1}   |   Κλίμακα: {2}",
                NetEngine.FmtRate(_curRxRate), NetEngine.FmtRate(_curTxRate), NetEngine.FmtRate(peak)),
                _fSmall, new Rectangle(12, 6, w - 24, 18), _fgMuted, TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        }

        private void DrawSeries(Graphics g, Rectangle chart, double[] data, double peak, Color color)
        {
            PointF[] pts = new PointF[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                float x = chart.Left + (float)i * (chart.Width - 2) / (data.Length - 1) + 1;
                float frac = (float)Math.Min(1.0, Math.Max(0.0, data[i] / peak));
                float y = chart.Bottom - 2 - frac * (chart.Height - 6);
                pts[i] = new PointF(x, y);
            }
            using (Pen p = new Pen(color, 1.9f)) g.DrawLines(p, pts);
        }

        private void KillSelectedConnProcess()
        {
            if (_lvConns.SelectedItems.Count == 0) return;
            NetConn c = _lvConns.SelectedItems[0].Tag as NetConn;
            if (c == null || c.Pid <= 4) return;
            if (MessageBox.Show(this, "Τερματισμός διεργασίας " + c.ProcessName + " (PID " + c.Pid + ");",
                "NillyNet Pro", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try { Process.GetProcessById(c.Pid).Kill(); SampleNetwork(); }
            catch (Exception ex)
            {
                string low = (ex.Message ?? "").ToLowerInvariant();
                string msg = low.Contains("access is denied")
                    ? "Δεν υπάρχει δικαίωμα τερματισμού αυτής της διεργασίας συστήματος (απαιτεί Administrator)."
                    : ex.Message;
                MessageBox.Show(this, msg, "NillyNet Pro", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void RunPingAsync()
        {
            string custom = _txtPingHost.Text.Trim();
            string[] hosts = string.IsNullOrEmpty(custom) || custom == "1.1.1.1" || custom == "8.8.8.8"
                ? new string[] { "1.1.1.1", "8.8.8.8", "9.9.9.9" }
                : new string[] { "1.1.1.1", "8.8.8.8", custom };
            _txtToolLog.AppendText("\r\n--- Ping Test (" + DateTime.Now.ToString("HH:mm:ss") + ") ---\r\n");
            Thread th = new Thread(delegate()
            {
                StringBuilder sb = new StringBuilder();
                using (Ping ping = new Ping())
                {
                    for (int i = 0; i < hosts.Length; i++)
                    {
                        try
                        {
                            PingReply r = ping.Send(hosts[i], 2000);
                            if (r.Status == IPStatus.Success)
                                sb.AppendLine(string.Format("  ✓ {0,-18} -> {1} ms  ({2})", hosts[i], r.RoundtripTime, r.RoundtripTime < 35 ? "Εξαιρετικό" : (r.RoundtripTime < 85 ? "Καλό" : "Αργό")));
                            else
                                sb.AppendLine(string.Format("  ✕ {0,-18} -> {1}", hosts[i], r.Status));
                        }
                        catch (Exception ex) { sb.AppendLine("  ✕ " + hosts[i] + " -> " + ex.Message); }
                    }
                }
                try { BeginInvoke((Action)delegate { _txtToolLog.AppendText(sb.ToString()); }); } catch { }
            });
            th.IsBackground = true; th.Start();
        }

        private void RunFlushDns()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("ipconfig.exe", "/flushdns")
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
                };
                using (Process p = Process.Start(psi))
                {
                    string outTxt = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    _txtToolLog.AppendText("\r\n[Flush DNS]\r\n" + outTxt.Trim() + "\r\n");
                    _lblStatus.Text = "✓ Καθαρίστηκε η DNS cache των Windows.";
                }
            }
            catch (Exception ex) { _txtToolLog.AppendText("\r\nΣφάλμα Flush DNS: " + ex.Message + "\r\n"); }
        }

        private void ApplyDns(string primary, string secondary)
        {
            string activeName = null;
            try
            {
                foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    { activeName = n.Name; break; }
                }
            }
            catch { }
            if (string.IsNullOrEmpty(activeName)) { _txtToolLog.AppendText("\r\nΔεν βρέθηκε ενεργός προσαρμογέας.\r\n"); return; }

            string cmd = string.IsNullOrEmpty(primary)
                ? string.Format("netsh interface ip set dns name=\"{0}\" dhcp", activeName)
                : string.Format("netsh interface ip set dns name=\"{0}\" static {1} && netsh interface ip add dns name=\"{0}\" {2} index=2", activeName, primary, secondary);
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
                using (Process p = Process.Start(psi)) { p.WaitForExit(8000); }
                _txtToolLog.AppendText("\r\n✓ Εφαρμόστηκε DNS στον προσαρμογέα [" + activeName + "]: " + (primary ?? "Αυτόματο DHCP") + "\r\n");
            }
            catch (Exception ex) { _txtToolLog.AppendText("\r\nΑκυρώθηκε ή απέτυχε η αλλαγή DNS: " + ex.Message + "\r\n"); }
        }

        private void DrawHdr(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            using (SolidBrush br = new SolidBrush(_bgPanel)) e.Graphics.FillRectangle(br, e.Bounds);
            using (Pen p = new Pen(_border)) e.Graphics.DrawLine(p, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            TextRenderer.DrawText(e.Graphics, e.Header.Text, _fSmall, new Rectangle(e.Bounds.X + 6, e.Bounds.Y, Math.Max(4, e.Bounds.Width - 10), e.Bounds.Height), _fgMuted, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }

        private void DrawSub(object sender, DrawListViewSubItemEventArgs e)
        {
            ListView lv = (ListView)sender;
            Color bg = e.Item.Selected ? _bgSel : ((e.ItemIndex % 2 == 0) ? _bgMain : _bgAlt);
            using (SolidBrush br = new SolidBrush(bg)) e.Graphics.FillRectangle(br, e.Bounds);
            Color fg = _fgMain;
            if (lv == _lvConns)
            {
                if (e.ColumnIndex == 5 && e.SubItem.Text == "ESTABLISHED") fg = _green;
                else if (e.ColumnIndex == 4 && e.SubItem.Text != "*:*") fg = _cyan;
                else if (e.ColumnIndex > 0) fg = _fgMuted;
            }
            else if (lv == _lvNearby)
            {
                if (e.ColumnIndex == 1) fg = (e.SubItem.Text == "5 GHz" || e.SubItem.Text == "6 GHz") ? _green : _accent;
                else if (e.ColumnIndex == 3) fg = _cyan;
                else if (e.ColumnIndex > 0) fg = _fgMuted;
            }
            else if (e.ColumnIndex > 0) fg = (e.ColumnIndex == 2) ? _cyan : _fgMuted;

            TextRenderer.DrawText(e.Graphics, e.SubItem.Text, e.ColumnIndex == 0 ? _fBold : _fSmall,
                new Rectangle(e.Bounds.X + 6, e.Bounds.Y, Math.Max(4, e.Bounds.Width - 10), e.Bounds.Height),
                fg, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }

        public void ShowInfoDialog()
        {
            double exeKb = 0;
            try { exeKb = new FileInfo(Assembly.GetExecutingAssembly().Location).Length / 1024.0; } catch { }
            long ramMb = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024);

            using (Form dlg = new Form())
            {
                dlg.Text = "NillyNet Pro — Ultra-Light Specs & Πληροφορίες";
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.ClientSize = new Size(515, 380);
                dlg.MaximizeBox = false; dlg.MinimizeBox = false;
                dlg.BackColor = _bgMain; dlg.ForeColor = _fgMain;
                Native.SetDarkTitlebar(dlg.Handle, _dark);

                PictureBox pic = new PictureBox { Size = new Size(42, 42), Location = new Point(18, 16), SizeMode = PictureBoxSizeMode.Zoom, Image = _logoBmp };
                Label hdr = new Label { Text = "NillyNet Pro v1.3.3", Location = new Point(70, 16), AutoSize = true, Font = new Font("Segoe UI", 13.0f, FontStyle.Bold) };
                Label sub = new Label { Text = "Ultra-Light Native Network Monitor, Wi-Fi Band/Speed Analyzer & DNS Tools", Location = new Point(72, 42), AutoSize = true, Font = _fSmall, ForeColor = _accent, UseMnemonic = false };

                Panel card = new Panel { Location = new Point(18, 72), Size = new Size(478, 200), BackColor = _bgPanel };
                Label specs = new Label
                {
                    Location = new Point(12, 10), Size = new Size(454, 182), Font = _fUi, ForeColor = _fgMain, UseMnemonic = false,
                    Text = string.Format(
                        "• Μέγεθος EXE στον δίσκο:  {0:0.0} KB  (0 εξωτερικά DLL · 0 WebView2)\n" +
                        "• Τρέχουσα RAM ανοιχτό:  ~{1} MB  |  Κλειστό:  0 MB RAM & 0% CPU\n" +
                        "• Αντικαθιστά:  Windows 11 Network Settings + Resource Monitor + Wi-Fi Analyzer\n" +
                        "• Πλήρες Wi-Fi Analyzer (On-Demand):  Band (2.4 / 5 / 6 GHz), Κανάλι,\n" +
                        "  Wi-Fi 4/5/6/6E/7, Rx/Tx Mbps, Σήμα % & dBm, Κοντινά Δίκτυα & Κωδικοί Wi-Fi\n" +
                        "• Ταχύτητα:  Native Win32 iphlpapi TCP/UDP + 0% background Wi-Fi polling",
                        exeKb, ramMb)
                };
                card.Controls.Add(specs);

                LinkLabel lnkSite = new LinkLabel { Text = "created by Nilly graphics (Sotiris Christos) — https://nillygraphics.com/", Location = new Point(18, 286), AutoSize = true, Font = _fSmall, LinkColor = _accent };
                lnkSite.LinkClicked += delegate { OpenUrl("https://nillygraphics.com/"); };
                LinkLabel lnkGit = new LinkLabel { Text = "GitHub (MIT Open Source · 0€): https://github.com/nillynp/nillynet-pro", Location = new Point(18, 308), AutoSize = true, Font = _fSmall, LinkColor = _cyan };
                lnkGit.LinkClicked += delegate { OpenUrl("https://github.com/nillynp/nillynet-pro"); };

                Button btnClose = new Button
                {
                    Text = "Κλείσιμο", DialogResult = DialogResult.OK, Location = new Point(408, 334), Size = new Size(88, 30),
                    FlatStyle = FlatStyle.Flat, BackColor = _accent, ForeColor = Color.FromArgb(20, 22, 26), Font = _fBold
                };
                btnClose.FlatAppearance.BorderSize = 0;

                dlg.Controls.AddRange(new Control[] { pic, hdr, sub, card, lnkSite, lnkGit, btnClose });
                dlg.AcceptButton = btnClose; dlg.CancelButton = btnClose;
                dlg.ShowDialog(this);
            }
        }

        private static string FindSiblingExe(string folder, string exeName)
        {
            try
            {
                string appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"NillySuite\" + folder + @"\" + exeName);
                if (File.Exists(appData)) return appData;
                DirectoryInfo par = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'));
                if (par != null)
                {
                    string sib = Path.Combine(Path.Combine(par.FullName, folder), exeName);
                    if (File.Exists(sib)) return sib;
                }
            }
            catch { }
            return null;
        }

        private void SendReportToNillyNote()
        {
            WifiLiveInfo wf = NetEngine.GetLiveWifiInfo();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== NillyNet Pro — Αναφορά Δικτύου & Wi-Fi ===");
            sb.AppendLine("Ημερομηνία: " + DateTime.Now.ToString("dd/MM/yyyy HH:mm"));
            sb.AppendLine("created by Nilly graphics (Sotiris Christos) — nillygraphics.com");
            sb.AppendLine("");
            sb.AppendLine("Προσαρμογέας: " + wf.AdapterName + " (" + wf.Description + ")");
            sb.AppendLine("IPv4: " + wf.IpV4 + "  |  Gateway: " + wf.Gateway + "  |  DNS: " + wf.Dns);
            sb.AppendLine("MAC: " + wf.MacAddress + "  |  Link: ↓ " + wf.RxMbps + " / ↑ " + wf.TxMbps);
            if (wf.HasWifi && wf.Connected)
                sb.AppendLine(string.Format("Wi-Fi: {0}  |  Band: {1}  |  Ch {2}  |  {3}  |  Σήμα: {4}% ({5} dBm)  |  {6}", wf.Ssid, wf.Band, wf.Channel, wf.WifiGen, wf.SignalPct, wf.EstDbm, wf.Auth));
            if (_txtToolLog != null && !string.IsNullOrEmpty(_txtToolLog.Text))
            {
                sb.AppendLine("");
                sb.AppendLine("--- Ping / DNS Log ---");
                sb.AppendLine(_txtToolLog.Text.Trim());
            }
            string txt = sb.ToString();
            string noteExe = FindSiblingExe("NillyNotePro", "NillyNotePro.exe");
            if (noteExe != null)
            {
                try
                {
                    string tmp = Path.Combine(Path.GetTempPath(), "NillyNet_Report_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt");
                    File.WriteAllText(tmp, txt, new UTF8Encoding(false));
                    Process.Start(new ProcessStartInfo(noteExe, "\"" + tmp + "\"") { WorkingDirectory = Path.GetDirectoryName(noteExe), UseShellExecute = true });
                    _lblStatus.Text = "↗ Η αναφορά δικτύου εστάλη στο NillyNote Pro!";
                    return;
                }
                catch { }
            }
            try { Clipboard.SetText(txt); _lblStatus.Text = "✓ Αντιγράφηκε η αναφορά δικτύου στο πρόχειρο."; } catch { }
        }

        private static void OpenUrl(string u) { try { Process.Start(new ProcessStartInfo(u) { UseShellExecute = true }); } catch { } }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Control | Keys.F)) { _txtSearch.Focus(); _txtSearch.SelectAll(); return true; }
            if (keyData == Keys.Space && !_txtSearch.Focused && !_txtPingHost.Focused) { _paused = !_paused; _btnPause.Text = _paused ? "▶" : "||"; return true; }
            if (keyData == Keys.F5) { if (_activeTab == 1) RefreshWifiTabAsync(); else SampleNetwork(); return true; }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        private static bool ReadSuiteDark(bool fallback)
        {
            try
            {
                string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"NillySuite\suite.theme");
                if (File.Exists(p))
                {
                    string s = File.ReadAllText(p, Encoding.ASCII).Trim();
                    if (s.Equals("light", StringComparison.OrdinalIgnoreCase)) return false;
                    if (s.Equals("dark", StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            catch { }
            return fallback;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { if (_timer != null) _timer.Dispose(); if (_logoBmp != null) _logoBmp.Dispose(); _fTitle.Dispose(); _fWifiHdr.Dispose(); _fUi.Dispose(); _fBold.Dispose(); _fSmall.Dispose(); _tip.Dispose(); }
            base.Dispose(disposing);
        }
    }

    internal static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            try { Native.SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (args != null && args.Length > 0 && args[0].Equals("--test-smoke", StringComparison.OrdinalIgnoreCase))
                return RunSmoke(args.Length > 1 ? args[1] : null, args.Length > 2 ? args[2] : null);

            string initFilter = null;
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i].Equals("--filter", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    { initFilter = args[i + 1]; break; }
                }
            }

            Application.Run(SuiteUpdater.Attach(new MainForm(false, initFilter), "nillynet-pro", "NillyNet-Pro", "Install_NillyNetPro.ps1"));
            return 0;
        }

        private static int RunSmoke(string logPath, string pngPath)
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                using (MainForm f = new MainForm(true))
                {
                    f.Show();
                    Application.DoEvents();
                    Thread.Sleep(250);
                    f.SampleNetwork();
                    Application.DoEvents();
                    int conns = f.ConnectionsCount;

                    if (!string.IsNullOrEmpty(pngPath))
                    {
                        using (Bitmap shot = new Bitmap(f.Width, f.Height))
                        {
                            f.DrawToBitmap(shot, new Rectangle(0, 0, f.Width, f.Height));
                            shot.Save(pngPath, ImageFormat.Png);
                        }
                    }

                    // Also exercise Wi-Fi Analyzer tab & narrow responsive width
                    f.SwitchTab(1);
                    f.RefreshWifiSyncForSmoke();
                    Application.DoEvents();
                    if (!string.IsNullOrEmpty(pngPath))
                    {
                        string p2 = Path.Combine(Path.GetDirectoryName(pngPath), Path.GetFileNameWithoutExtension(pngPath) + "_wifi.png");
                        using (Bitmap shot2 = new Bitmap(f.Width, f.Height))
                        {
                            f.DrawToBitmap(shot2, new Rectangle(0, 0, f.Width, f.Height));
                            shot2.Save(p2, ImageFormat.Png);
                        }
                    }

                    double exeKb = new FileInfo(Assembly.GetExecutingAssembly().Location).Length / 1024.0;
                    bool pass = (conns >= 5 && f.IsHandleCreated && exeKb < 150.0);
                    sb.AppendLine("CONNECTIONS_COUNT=" + conns);
                    sb.AppendLine("EXE_KB=" + exeKb.ToString("0.0"));
                    sb.AppendLine("WINDOW_OPENED_OK=" + f.IsHandleCreated);
                    sb.AppendLine("SMOKE_RESULT=" + (pass ? "PASS" : "FAIL"));
                    f.Close();
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("SMOKE_RESULT=FAIL");
                sb.AppendLine(ex.ToString());
                if (!string.IsNullOrEmpty(logPath)) File.WriteAllText(logPath, sb.ToString(), Encoding.UTF8);
                return 1;
            }
            if (!string.IsNullOrEmpty(logPath)) File.WriteAllText(logPath, sb.ToString(), Encoding.UTF8);
            return 0;
        }
    }

    // ========================================================================
    // BUILT-IN ULTRA-LIGHT AUTO-UPDATER (1x/24h shared CDN check · SHA-256)
    // ========================================================================
    internal static class SuiteUpdater
    {
        private const string CATALOG_URL = "https://raw.githubusercontent.com/nillynp/nillyhub/main/catalog.json";

        public static T Attach<T>(T form, string repoName, string pkgPrefix, string installerScript) where T : System.Windows.Forms.Form
        {
            if (form == null) return null;
            form.Shown += delegate
            {
                System.Threading.Thread th = new System.Threading.Thread(delegate()
                {
                    try
                    {
                        System.Threading.Thread.Sleep(2200);
                        if (form.IsDisposed) return;
                        string curTag, newTag;
                        if (!CheckForUpdate(repoName, out curTag, out newTag)) return;
                        if (form.IsDisposed || !form.IsHandleCreated) return;
                        form.BeginInvoke((System.Action)delegate
                        {
                            if (form.IsDisposed || form.FormBorderStyle == System.Windows.Forms.FormBorderStyle.None) return;
                            ShowUpdateBanner(form, repoName, pkgPrefix, installerScript, curTag, newTag);
                        });
                    }
                    catch { }
                });
                th.IsBackground = true;
                th.Start();
            };
            return form;
        }

        private static void ShowUpdateBanner(System.Windows.Forms.Form form, string repoName, string pkgPrefix, string installerScript, string curTag, string newTag)
        {
            System.Drawing.Font fTxt = new System.Drawing.Font("Segoe UI", 8.5f, System.Drawing.FontStyle.Regular);
            System.Drawing.Font fBtn = new System.Drawing.Font("Segoe UI", 8.2f, System.Drawing.FontStyle.Bold);

            System.Windows.Forms.Panel bar = new System.Windows.Forms.Panel();
            bar.Dock = System.Windows.Forms.DockStyle.Top;
            bar.Height = 28;
            bar.BackColor = System.Drawing.Color.FromArgb(40, 29, 18);
            bar.Padding = new System.Windows.Forms.Padding(10, 0, 8, 1);
            bar.Paint += delegate(object s, System.Windows.Forms.PaintEventArgs e)
            {
                using (System.Drawing.Pen p = new System.Drawing.Pen(System.Drawing.Color.FromArgb(252, 150, 31)))
                    e.Graphics.DrawLine(p, 0, bar.Height - 1, bar.Width, bar.Height - 1);
            };

            System.Windows.Forms.Button btnClose = new System.Windows.Forms.Button();
            btnClose.Text = "×";
            btnClose.Dock = System.Windows.Forms.DockStyle.Right;
            btnClose.Width = 26;
            btnClose.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.BackColor = System.Drawing.Color.Transparent;
            btnClose.ForeColor = System.Drawing.Color.FromArgb(200, 170, 130);
            btnClose.Font = fBtn;
            btnClose.Cursor = System.Windows.Forms.Cursors.Hand;
            btnClose.TabStop = false;
            btnClose.Click += delegate { bar.Dispose(); };

            System.Windows.Forms.Button btnUpd = new System.Windows.Forms.Button();
            btnUpd.Text = "Ενημέρωση";
            btnUpd.Dock = System.Windows.Forms.DockStyle.Right;
            btnUpd.Width = 88;
            btnUpd.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            btnUpd.FlatAppearance.BorderSize = 0;
            btnUpd.BackColor = System.Drawing.Color.FromArgb(252, 150, 31);
            btnUpd.ForeColor = System.Drawing.Color.FromArgb(20, 22, 26);
            btnUpd.Font = fBtn;
            btnUpd.Cursor = System.Windows.Forms.Cursors.Hand;
            btnUpd.TabStop = false;

            System.Windows.Forms.Label lbl = new System.Windows.Forms.Label();
            lbl.Dock = System.Windows.Forms.DockStyle.Fill;
            lbl.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            lbl.Font = fTxt;
            lbl.ForeColor = System.Drawing.Color.FromArgb(255, 185, 95);
            lbl.UseMnemonic = false;
            lbl.Text = "Νέα έκδοση " + newTag + " διαθέσιμη (έχεις " + curTag + ")";

            btnUpd.Click += delegate
            {
                btnUpd.Enabled = false;
                btnUpd.Text = "Λήψη...";
                System.Threading.Thread uth = new System.Threading.Thread(delegate()
                {
                    try
                    {
                        ApplySelfUpdate(repoName, pkgPrefix, installerScript,
                            delegate(string st)
                            {
                                try { if (!form.IsDisposed) form.BeginInvoke((System.Action)delegate { lbl.Text = st; }); } catch { }
                            },
                            delegate
                            {
                                try { if (!form.IsDisposed) form.BeginInvoke((System.Action)delegate { System.Windows.Forms.Application.Exit(); }); } catch { }
                            });
                    }
                    catch (System.Exception ex)
                    {
                        try
                        {
                            if (!form.IsDisposed) form.BeginInvoke((System.Action)delegate
                            {
                                lbl.Text = "Σφάλμα ενημέρωσης: " + ex.Message;
                                btnUpd.Text = "Ενημέρωση";
                                btnUpd.Enabled = true;
                            });
                        }
                        catch { }
                    }
                });
                uth.IsBackground = true;
                uth.Start();
            };

            bar.Disposed += delegate { fTxt.Dispose(); fBtn.Dispose(); };
            bar.Controls.Add(lbl);
            bar.Controls.Add(btnUpd);
            bar.Controls.Add(btnClose);
            form.Controls.Add(bar);
        }

        private static bool TryParseVer(string raw, out System.Version ver)
        {
            ver = null;
            if (string.IsNullOrEmpty(raw)) return false;
            string s = raw.Trim();
            if (s.StartsWith("v", System.StringComparison.OrdinalIgnoreCase)) s = s.Substring(1);
            string[] p = s.Split('.');
            if (p.Length < 2 || p.Length > 4) return false;
            int maj, min, pat = 0;
            if (!int.TryParse(p[0], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out maj)) return false;
            if (!int.TryParse(p[1], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out min)) return false;
            if (p.Length >= 3 && !int.TryParse(p[2], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out pat)) return false;
            ver = new System.Version(maj, min, pat, 0);
            return true;
        }

        private static string FmtVer(System.Version v)
        {
            return v.Build > 0
                ? string.Format(System.Globalization.CultureInfo.InvariantCulture, "v{0}.{1}.{2}", v.Major, v.Minor, v.Build)
                : string.Format(System.Globalization.CultureInfo.InvariantCulture, "v{0}.{1}", v.Major, v.Minor);
        }

        public static bool CheckForUpdate(string repoName, out string curTag, out string newTag)
        {
            curTag = null; newTag = null;
            System.Version rawCur = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            System.Version curVer = new System.Version(rawCur.Major, rawCur.Minor, rawCur.Build >= 0 ? rawCur.Build : 0, 0);
            curTag = FmtVer(curVer);

            string suiteDir = System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData), "NillySuite");
            string cachePath = System.IO.Path.Combine(suiteDir, ".nillyhub_catalog.json");
            string json = null;
            try
            {
                if (System.IO.File.Exists(cachePath))
                {
                    System.DateTime wt = System.IO.File.GetLastWriteTimeUtc(cachePath);
                    if ((System.DateTime.UtcNow - wt).TotalHours < 24.0)
                    {
                        string cached = System.IO.File.ReadAllText(cachePath, System.Text.Encoding.UTF8);
                        if (cached.IndexOf("\"latestVersion\"", System.StringComparison.Ordinal) >= 0) json = cached;
                    }
                }
            }
            catch { }

            if (string.IsNullOrEmpty(json))
            {
                json = HttpGetText(CATALOG_URL, 5000);
                if (string.IsNullOrEmpty(json) || json.Length > 256 * 1024) return false;
                try
                {
                    System.IO.Directory.CreateDirectory(suiteDir);
                    System.IO.File.WriteAllText(cachePath, json, new System.Text.UTF8Encoding(false));
                }
                catch { }
            }

            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(
                json,
                "\"repo\"\\s*:\\s*\"" + System.Text.RegularExpressions.Regex.Escape(repoName) + "\"[^\\}]{0,500}?\"latestVersion\"\\s*:\\s*\"(v[0-9]+\\.[0-9]+(?:\\.[0-9]+)?)\"",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (!m.Success) return false;
            System.Version remVer;
            if (!TryParseVer(m.Groups[1].Value, out remVer) || remVer <= curVer) return false;
            newTag = FmtVer(remVer);
            return true;
        }

        private static string HttpGetText(string url, int timeoutMs)
        {
            try { System.Net.ServicePointManager.SecurityProtocol |= (System.Net.SecurityProtocolType)3072 | System.Net.SecurityProtocolType.Tls12; } catch { }
            System.Net.HttpWebRequest req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
            req.UserAgent = "NillySuite-Updater/1.0 (https://nillygraphics.com/)";
            req.Accept = "application/vnd.github+json, application/json";
            req.AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate;
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            using (System.Net.HttpWebResponse resp = (System.Net.HttpWebResponse)req.GetResponse())
            using (System.IO.Stream st = resp.GetResponseStream())
            using (System.IO.StreamReader sr = new System.IO.StreamReader(st, System.Text.Encoding.UTF8))
                return sr.ReadToEnd();
        }

        private static string ExtractAssetBlock(string json, string assetName)
        {
            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(
                json, "\"name\"\\s*:\\s*\"" + System.Text.RegularExpressions.Regex.Escape(assetName) + "\"");
            if (!m.Success) return null;
            int start = m.Index;
            int depth = 0;
            while (start > 0)
            {
                char c = json[start];
                if (c == '}') depth++;
                else if (c == '{') { if (depth == 0) break; depth--; }
                start--;
            }
            int end = start;
            depth = 0;
            bool inStr = false;
            for (int i = start; i < json.Length; i++)
            {
                char c = json[i];
                if (c == '"' && (i == 0 || json[i - 1] != '\\')) inStr = !inStr;
                if (inStr) continue;
                if (c == '{') depth++;
                else if (c == '}') { depth--; if (depth == 0) { end = i; break; } }
            }
            return end > start ? json.Substring(start, end - start + 1) : null;
        }

        public static void ApplySelfUpdate(string repoName, string pkgPrefix, string installerScript, System.Action<string> onStatus, System.Action onExit)
        {
            string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string appDir = System.IO.Path.GetDirectoryName(exePath);
            if (System.IO.Directory.Exists(System.IO.Path.Combine(appDir, ".git")))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://github.com/nillynp/" + repoName + "/releases/latest") { UseShellExecute = true });
                if (onStatus != null) onStatus("Άνοιξε το GitHub Release (φάκελος Git).");
                return;
            }

            if (onStatus != null) onStatus("Έλεγχος SHA-256 στο GitHub...");
            string relJson = HttpGetText("https://api.github.com/repos/nillynp/" + repoName + "/releases/latest", 12000);
            if (string.IsNullOrEmpty(relJson)) throw new System.IO.InvalidDataException("Κενή απόκριση GitHub.");
            if (System.Text.RegularExpressions.Regex.IsMatch(relJson, "\"draft\"\\s*:\\s*true") ||
                System.Text.RegularExpressions.Regex.IsMatch(relJson, "\"prerelease\"\\s*:\\s*true"))
                throw new System.IO.InvalidDataException("Μη σταθερή έκδοση.");

            System.Text.RegularExpressions.Match tm = System.Text.RegularExpressions.Regex.Match(relJson, "\"tag_name\"\\s*:\\s*\"(v[0-9]+\\.[0-9]+(?:\\.[0-9]+)?)\"");
            if (!tm.Success) throw new System.IO.InvalidDataException("Μη έγκυρο tag έκδοσης.");
            string tag = tm.Groups[1].Value;

            System.Version curRaw = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            System.Version curVer = new System.Version(curRaw.Major, curRaw.Minor, curRaw.Build >= 0 ? curRaw.Build : 0, 0);
            System.Version remVer;
            if (!TryParseVer(tag, out remVer) || remVer <= curVer)
                throw new System.InvalidOperationException("Έχεις ήδη την τελευταία έκδοση.");

            string zipName = pkgPrefix + "-" + tag + "-Portable.zip";
            string expectedUrl = "https://github.com/nillynp/" + repoName + "/releases/download/" + tag + "/" + zipName;
            string blk = ExtractAssetBlock(relJson, zipName);
            if (string.IsNullOrEmpty(blk)) throw new System.IO.FileNotFoundException("Δεν βρέθηκε το Portable ZIP.");
            if (!System.Text.RegularExpressions.Regex.IsMatch(blk, "\"state\"\\s*:\\s*\"uploaded\""))
                throw new System.IO.InvalidDataException("Το αρχείο δεν είναι έτοιμο.");
            System.Text.RegularExpressions.Match um = System.Text.RegularExpressions.Regex.Match(blk, "\"browser_download_url\"\\s*:\\s*\"([^\"]+)\"");
            if (!um.Success || !string.Equals(um.Groups[1].Value, expectedUrl, System.StringComparison.Ordinal))
                throw new System.IO.InvalidDataException("Μη έγκυρο URL λήψης.");
            System.Text.RegularExpressions.Match dm = System.Text.RegularExpressions.Regex.Match(blk, "\"digest\"\\s*:\\s*\"sha256:([0-9a-f]{64})\"");
            if (!dm.Success) throw new System.IO.InvalidDataException("Απουσιάζει SHA-256.");
            string expectedSha = dm.Groups[1].Value;

            string tmpDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "NillyUpd-" + System.Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(tmpDir);
            string zipFile = System.IO.Path.Combine(tmpDir, "pkg.zip");

            if (onStatus != null) onStatus("Λήψη " + tag + "...");
            try { System.Net.ServicePointManager.SecurityProtocol |= (System.Net.SecurityProtocolType)3072 | System.Net.SecurityProtocolType.Tls12; } catch { }
            System.Net.HttpWebRequest dreq = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(expectedUrl);
            dreq.UserAgent = "NillySuite-Updater/1.0 (https://nillygraphics.com/)";
            dreq.Timeout = 20000;
            dreq.ReadWriteTimeout = 30000;
            using (System.Net.HttpWebResponse dresp = (System.Net.HttpWebResponse)dreq.GetResponse())
            using (System.IO.Stream src = dresp.GetResponseStream())
            using (System.IO.FileStream dst = new System.IO.FileStream(zipFile, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None))
            {
                byte[] buf = new byte[16384];
                int n; long total = 0;
                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                {
                    total += n;
                    if (total > 32L * 1024L * 1024L) throw new System.IO.InvalidDataException("Υπέρβαση μεγέθους ZIP.");
                    dst.Write(buf, 0, n);
                }
            }

            if (onStatus != null) onStatus("Επαλήθευση SHA-256...");
            string actualSha;
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
            using (System.IO.FileStream fs = System.IO.File.OpenRead(zipFile))
            {
                byte[] hash = sha.ComputeHash(fs);
                System.Text.StringBuilder sb = new System.Text.StringBuilder(64);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
                actualSha = sb.ToString();
            }
            if (!string.Equals(actualSha, expectedSha, System.StringComparison.OrdinalIgnoreCase))
            {
                try { System.IO.Directory.Delete(tmpDir, true); } catch { }
                throw new System.IO.InvalidDataException("Αποτυχία ελέγχου SHA-256.");
            }

            if (onStatus != null) onStatus("Εγκατάσταση " + tag + " & επανεκκίνηση...");
            string ps1 = System.IO.Path.Combine(tmpDir, "apply.ps1");
            string script =
                "param($myPid,$zip,$appDir,$instName,$exePath,$tag)\r\n" +
                "for($i=0;$i -lt 60;$i++){ if(-not (Get-Process -Id $myPid -ErrorAction SilentlyContinue)){break}; Start-Sleep -Milliseconds 150 }\r\n" +
                "Add-Type -AssemblyName System.IO.Compression.FileSystem\r\n" +
                "$za = [System.IO.Compression.ZipFile]::OpenRead($zip)\r\n" +
                "try {\r\n" +
                "  $pref = $null; $shared = $true\r\n" +
                "  foreach($e in $za.Entries){ $fn=$e.FullName -replace '\\\\','/'; $sl=$fn.IndexOf('/'); if($sl -le 0){$shared=$false;break}; $p=$fn.Substring(0,$sl+1); if(-not $pref){$pref=$p}elseif(-not $pref.Equals($p,[StringComparison]::OrdinalIgnoreCase)){$shared=$false;break} }\r\n" +
                "  $rootFull = [System.IO.Path]::GetFullPath($appDir).TrimEnd('\\') + '\\'\r\n" +
                "  foreach($e in $za.Entries){\r\n" +
                "    $rel = $e.FullName -replace '\\\\','/'\r\n" +
                "    if($shared -and $pref -and $rel.StartsWith($pref,[StringComparison]::OrdinalIgnoreCase)){ $rel=$rel.Substring($pref.Length) }\r\n" +
                "    if([string]::IsNullOrEmpty($rel) -or $rel.EndsWith('/') -or $rel.Contains(':')){ continue }\r\n" +
                "    $dst = [System.IO.Path]::GetFullPath((Join-Path $appDir ($rel -replace '/','\\')))\r\n" +
                "    if(-not $dst.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)){ continue }\r\n" +
                "    $par = Split-Path -Parent $dst; if($par){ New-Item -ItemType Directory -Force -Path $par | Out-Null }\r\n" +
                "    for($k=0;$k -lt 5;$k++){ try { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e,$dst,$true); break } catch { Start-Sleep -Milliseconds 250 } }\r\n" +
                "  }\r\n" +
                "} finally { $za.Dispose() }\r\n" +
                "$bak = $exePath + '.bak'\r\n" +
                "if(Test-Path $exePath){ Copy-Item -LiteralPath $exePath -Destination $bak -Force -ErrorAction SilentlyContinue; for($k=0;$k -lt 5;$k++){ try { Remove-Item -LiteralPath $exePath -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 250 } } }\r\n" +
                "Get-ChildItem (Join-Path $appDir 'desktop') -Filter '*.cs' -ErrorAction SilentlyContinue | ForEach-Object { $_.LastWriteTimeUtc = [DateTime]::UtcNow }\r\n" +
                "if($instName -and (Test-Path (Join-Path $appDir $instName))){ & (Join-Path $appDir $instName) -Silent 2>$null | Out-Null }\r\n" +
                "if(-not (Test-Path $exePath) -and (Test-Path $bak)){ Move-Item -LiteralPath $bak -Destination $exePath -Force -ErrorAction SilentlyContinue } else { Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue }\r\n" +
                "if($tag){ Set-Content -LiteralPath (Join-Path $appDir '.nilly_version') -Value $tag -Encoding UTF8 -ErrorAction SilentlyContinue }\r\n" +
                "if(Test-Path $exePath){ Start-Process -FilePath $exePath -WorkingDirectory $appDir }\r\n" +
                "Start-Sleep -Milliseconds 400\r\n" +
                "Remove-Item -LiteralPath (Split-Path $zip) -Recurse -Force -ErrorAction SilentlyContinue\r\n";
            System.IO.File.WriteAllText(ps1, script, new System.Text.UTF8Encoding(false));

            int myPid = System.Diagnostics.Process.GetCurrentProcess().Id;
            System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo(
                "powershell.exe",
                "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + ps1 + "\" " +
                myPid + " \"" + zipFile + "\" \"" + appDir + "\" \"" + installerScript + "\" \"" + exePath + "\" \"" + tag + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            System.Diagnostics.Process.Start(psi);
            if (onExit != null) onExit();
        }
    }

    // ========================================================================
    // ARIAKIT-INSPIRED MINIMAL VECTOR UI KIT (Zero DLLs · 1.5px Stroke Icons)
    // ========================================================================
    internal enum AkKind { Primary, Secondary, Ghost, Tab, AccentOutline, Danger }

    internal enum AkIcon
    {
        None, Refresh, Sun, Moon, Search, Pin, Info, Play, Pause, Stop,
        Plus, Minus, Close, Up, Down, Folder, Copy, Trash, Check, Swap,
        Download, Link, Split, Pipette, Bolt, List, Filter, Shield, Lock, Unlock,
        Edit, Save, External, Bold, Italic, Undo, ChevLeft, ChevRight, Star
    }

    internal static class AkDraw
    {
        public static System.Drawing.Drawing2D.GraphicsPath RoundRect(float x, float y, float w, float h, float r)
        {
            System.Drawing.Drawing2D.GraphicsPath p = new System.Drawing.Drawing2D.GraphicsPath();
            float d = System.Math.Min(r * 2f, System.Math.Min(w, h));
            if (d <= 0.5f) { p.AddRectangle(new System.Drawing.RectangleF(x, y, w, h)); return p; }
            p.AddArc(x, y, d, d, 180, 90);
            p.AddArc(x + w - d, y, d, d, 270, 90);
            p.AddArc(x + w - d, y + h - d, d, d, 0, 90);
            p.AddArc(x, y + h - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static void DrawIcon(System.Drawing.Graphics g, AkIcon icon, float cx, float cy, float sz, System.Drawing.Color color)
        {
            if (icon == AkIcon.None) return;
            System.Drawing.Drawing2D.SmoothingMode oldSm = g.SmoothingMode;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            float r = sz * 0.5f;
            using (System.Drawing.Pen pen = new System.Drawing.Pen(color, 1.5f))
            using (System.Drawing.SolidBrush br = new System.Drawing.SolidBrush(color))
            {
                pen.StartCap = System.Drawing.Drawing2D.LineCap.Round;
                pen.EndCap = System.Drawing.Drawing2D.LineCap.Round;
                pen.LineJoin = System.Drawing.Drawing2D.LineJoin.Round;
                switch (icon)
                {
                    case AkIcon.Refresh:
                        g.DrawArc(pen, cx - r * 0.82f, cy - r * 0.82f, r * 1.64f, r * 1.64f, -55, 295);
                        g.DrawLine(pen, cx + r * 0.28f, cy - r * 0.85f, cx + r * 0.62f, cy - r * 0.52f);
                        g.DrawLine(pen, cx + r * 0.62f, cy - r * 0.52f, cx + r * 0.20f, cy - r * 0.42f);
                        break;
                    case AkIcon.Sun:
                        g.DrawEllipse(pen, cx - r * 0.42f, cy - r * 0.42f, r * 0.84f, r * 0.84f);
                        for (int i = 0; i < 8; i++)
                        {
                            double a = i * System.Math.PI / 4.0;
                            float x1 = cx + (float)(System.Math.Cos(a) * r * 0.68f);
                            float y1 = cy + (float)(System.Math.Sin(a) * r * 0.68f);
                            float x2 = cx + (float)(System.Math.Cos(a) * r * 0.94f);
                            float y2 = cy + (float)(System.Math.Sin(a) * r * 0.94f);
                            g.DrawLine(pen, x1, y1, x2, y2);
                        }
                        break;
                    case AkIcon.Moon:
                        g.DrawArc(pen, cx - r * 0.78f, cy - r * 0.78f, r * 1.56f, r * 1.56f, 40, 235);
                        g.DrawArc(pen, cx - r * 0.30f, cy - r * 0.92f, r * 1.32f, r * 1.32f, 115, 130);
                        break;
                    case AkIcon.Search:
                        g.DrawEllipse(pen, cx - r * 0.82f, cy - r * 0.82f, r * 1.24f, r * 1.24f);
                        g.DrawLine(pen, cx + r * 0.25f, cy + r * 0.25f, cx + r * 0.82f, cy + r * 0.82f);
                        break;
                    case AkIcon.Pin:
                        g.DrawLine(pen, cx - r * 0.48f, cy - r * 0.72f, cx + r * 0.48f, cy - r * 0.72f);
                        g.DrawLine(pen, cx - r * 0.34f, cy - r * 0.72f, cx - r * 0.56f, cy + r * 0.14f);
                        g.DrawLine(pen, cx + r * 0.34f, cy - r * 0.72f, cx + r * 0.56f, cy + r * 0.14f);
                        g.DrawLine(pen, cx - r * 0.66f, cy + r * 0.14f, cx + r * 0.66f, cy + r * 0.14f);
                        g.DrawLine(pen, cx, cy + r * 0.14f, cx, cy + r * 0.86f);
                        break;
                    case AkIcon.Info:
                        g.DrawEllipse(pen, cx - r * 0.85f, cy - r * 0.85f, r * 1.70f, r * 1.70f);
                        g.DrawLine(pen, cx, cy - r * 0.08f, cx, cy + r * 0.48f);
                        g.FillEllipse(br, cx - 1.1f, cy - r * 0.52f, 2.2f, 2.2f);
                        break;
                    case AkIcon.Play:
                        g.FillPolygon(br, new System.Drawing.PointF[] {
                            new System.Drawing.PointF(cx - r * 0.45f, cy - r * 0.68f),
                            new System.Drawing.PointF(cx + r * 0.68f, cy),
                            new System.Drawing.PointF(cx - r * 0.45f, cy + r * 0.68f)
                        });
                        break;
                    case AkIcon.Pause:
                        g.DrawLine(pen, cx - r * 0.36f, cy - r * 0.62f, cx - r * 0.36f, cy + r * 0.62f);
                        g.DrawLine(pen, cx + r * 0.36f, cy - r * 0.62f, cx + r * 0.36f, cy + r * 0.62f);
                        break;
                    case AkIcon.Stop:
                        g.FillRectangle(br, cx - r * 0.56f, cy - r * 0.56f, r * 1.12f, r * 1.12f);
                        break;
                    case AkIcon.Plus:
                        g.DrawLine(pen, cx - r * 0.68f, cy, cx + r * 0.68f, cy);
                        g.DrawLine(pen, cx, cy - r * 0.68f, cx, cy + r * 0.68f);
                        break;
                    case AkIcon.Minus:
                        g.DrawLine(pen, cx - r * 0.68f, cy, cx + r * 0.68f, cy);
                        break;
                    case AkIcon.Close:
                        g.DrawLine(pen, cx - r * 0.58f, cy - r * 0.58f, cx + r * 0.58f, cy + r * 0.58f);
                        g.DrawLine(pen, cx + r * 0.58f, cy - r * 0.58f, cx - r * 0.58f, cy + r * 0.58f);
                        break;
                    case AkIcon.Up:
                        g.DrawLine(pen, cx, cy + r * 0.68f, cx, cy - r * 0.64f);
                        g.DrawLine(pen, cx - r * 0.52f, cy - r * 0.14f, cx, cy - r * 0.66f);
                        g.DrawLine(pen, cx + r * 0.52f, cy - r * 0.14f, cx, cy - r * 0.66f);
                        break;
                    case AkIcon.Down:
                        g.DrawLine(pen, cx, cy - r * 0.68f, cx, cy + r * 0.64f);
                        g.DrawLine(pen, cx - r * 0.52f, cy + r * 0.14f, cx, cy + r * 0.66f);
                        g.DrawLine(pen, cx + r * 0.52f, cy + r * 0.14f, cx, cy + r * 0.66f);
                        break;
                    case AkIcon.Folder:
                        g.DrawPolygon(pen, new System.Drawing.PointF[] {
                            new System.Drawing.PointF(cx - r * 0.85f, cy - r * 0.56f),
                            new System.Drawing.PointF(cx - r * 0.22f, cy - r * 0.56f),
                            new System.Drawing.PointF(cx - r * 0.04f, cy - r * 0.34f),
                            new System.Drawing.PointF(cx + r * 0.85f, cy - r * 0.34f),
                            new System.Drawing.PointF(cx + r * 0.85f, cy + r * 0.64f),
                            new System.Drawing.PointF(cx - r * 0.85f, cy + r * 0.64f)
                        });
                        break;
                    case AkIcon.Copy:
                        g.DrawRectangle(pen, cx - r * 0.26f, cy - r * 0.26f, r * 1.02f, r * 1.02f);
                        g.DrawLine(pen, cx - r * 0.68f, cy + r * 0.30f, cx - r * 0.68f, cy - r * 0.68f);
                        g.DrawLine(pen, cx - r * 0.68f, cy - r * 0.68f, cx + r * 0.30f, cy - r * 0.68f);
                        break;
                    case AkIcon.Trash:
                        g.DrawLine(pen, cx - r * 0.76f, cy - r * 0.44f, cx + r * 0.76f, cy - r * 0.44f);
                        g.DrawLine(pen, cx - r * 0.28f, cy - r * 0.74f, cx + r * 0.28f, cy - r * 0.74f);
                        g.DrawRectangle(pen, cx - r * 0.54f, cy - r * 0.42f, r * 1.08f, r * 1.16f);
                        break;
                    case AkIcon.Check:
                        g.DrawLine(pen, cx - r * 0.68f, cy + r * 0.04f, cx - r * 0.14f, cy + r * 0.58f);
                        g.DrawLine(pen, cx - r * 0.14f, cy + r * 0.58f, cx + r * 0.74f, cy - r * 0.52f);
                        break;
                    case AkIcon.Swap:
                        g.DrawLine(pen, cx - r * 0.70f, cy - r * 0.32f, cx + r * 0.70f, cy - r * 0.32f);
                        g.DrawLine(pen, cx + r * 0.32f, cy - r * 0.68f, cx + r * 0.72f, cy - r * 0.32f);
                        g.DrawLine(pen, cx + r * 0.70f, cy + r * 0.34f, cx - r * 0.70f, cy + r * 0.34f);
                        g.DrawLine(pen, cx - r * 0.32f, cy + r * 0.70f, cx - r * 0.72f, cy + r * 0.34f);
                        break;
                    case AkIcon.Download:
                        g.DrawLine(pen, cx, cy - r * 0.72f, cx, cy + r * 0.28f);
                        g.DrawLine(pen, cx - r * 0.44f, cy - r * 0.12f, cx, cy + r * 0.32f);
                        g.DrawLine(pen, cx + r * 0.44f, cy - r * 0.12f, cx, cy + r * 0.32f);
                        g.DrawLine(pen, cx - r * 0.74f, cy + r * 0.72f, cx + r * 0.74f, cy + r * 0.72f);
                        break;
                    case AkIcon.Link:
                    case AkIcon.External:
                        g.DrawLine(pen, cx - r * 0.58f, cy + r * 0.58f, cx + r * 0.62f, cy - r * 0.62f);
                        g.DrawLine(pen, cx - r * 0.06f, cy - r * 0.64f, cx + r * 0.64f, cy - r * 0.64f);
                        g.DrawLine(pen, cx + r * 0.64f, cy - r * 0.64f, cx + r * 0.64f, cy + r * 0.06f);
                        break;
                    case AkIcon.Split:
                        g.DrawRectangle(pen, cx - r * 0.82f, cy - r * 0.64f, r * 1.64f, r * 1.28f);
                        g.DrawLine(pen, cx, cy - r * 0.64f, cx, cy + r * 0.64f);
                        break;
                    case AkIcon.Pipette:
                        g.DrawLine(pen, cx - r * 0.66f, cy + r * 0.66f, cx + r * 0.40f, cy - r * 0.40f);
                        g.DrawLine(pen, cx + r * 0.12f, cy - r * 0.68f, cx + r * 0.68f, cy - r * 0.12f);
                        break;
                    case AkIcon.Bolt:
                        g.DrawPolygon(pen, new System.Drawing.PointF[] {
                            new System.Drawing.PointF(cx + r * 0.14f, cy - r * 0.82f),
                            new System.Drawing.PointF(cx - r * 0.62f, cy + r * 0.08f),
                            new System.Drawing.PointF(cx - r * 0.04f, cy + r * 0.08f),
                            new System.Drawing.PointF(cx - r * 0.18f, cy + r * 0.82f),
                            new System.Drawing.PointF(cx + r * 0.62f, cy - r * 0.10f),
                            new System.Drawing.PointF(cx + r * 0.04f, cy - r * 0.10f)
                        });
                        break;
                    case AkIcon.List:
                        g.DrawLine(pen, cx - r * 0.72f, cy - r * 0.46f, cx + r * 0.72f, cy - r * 0.46f);
                        g.DrawLine(pen, cx - r * 0.72f, cy, cx + r * 0.72f, cy);
                        g.DrawLine(pen, cx - r * 0.72f, cy + r * 0.46f, cx + r * 0.72f, cy + r * 0.46f);
                        break;
                    case AkIcon.Filter:
                        g.DrawPolygon(pen, new System.Drawing.PointF[] {
                            new System.Drawing.PointF(cx - r * 0.78f, cy - r * 0.60f),
                            new System.Drawing.PointF(cx + r * 0.78f, cy - r * 0.60f),
                            new System.Drawing.PointF(cx + r * 0.16f, cy + r * 0.08f),
                            new System.Drawing.PointF(cx + r * 0.16f, cy + r * 0.68f),
                            new System.Drawing.PointF(cx - r * 0.16f, cy + r * 0.52f),
                            new System.Drawing.PointF(cx - r * 0.16f, cy + r * 0.08f)
                        });
                        break;
                    case AkIcon.Shield:
                        g.DrawPolygon(pen, new System.Drawing.PointF[] {
                            new System.Drawing.PointF(cx, cy - r * 0.82f),
                            new System.Drawing.PointF(cx + r * 0.72f, cy - r * 0.44f),
                            new System.Drawing.PointF(cx + r * 0.58f, cy + r * 0.34f),
                            new System.Drawing.PointF(cx, cy + r * 0.82f),
                            new System.Drawing.PointF(cx - r * 0.58f, cy + r * 0.34f),
                            new System.Drawing.PointF(cx - r * 0.72f, cy - r * 0.44f)
                        });
                        break;
                    case AkIcon.Lock:
                        g.DrawRectangle(pen, cx - r * 0.58f, cy - r * 0.08f, r * 1.16f, r * 0.84f);
                        g.DrawArc(pen, cx - r * 0.38f, cy - r * 0.76f, r * 0.76f, r * 0.84f, 180, 180);
                        break;
                    case AkIcon.Unlock:
                        g.DrawRectangle(pen, cx - r * 0.58f, cy - r * 0.08f, r * 1.16f, r * 0.84f);
                        g.DrawArc(pen, cx - r * 0.38f, cy - r * 0.76f, r * 0.76f, r * 0.84f, 180, 130);
                        break;
                    case AkIcon.Save:
                        g.DrawRectangle(pen, cx - r * 0.72f, cy - r * 0.72f, r * 1.44f, r * 1.44f);
                        g.DrawRectangle(pen, cx - r * 0.42f, cy - r * 0.72f, r * 0.72f, r * 0.48f);
                        g.DrawRectangle(pen, cx - r * 0.44f, cy + r * 0.14f, r * 0.88f, r * 0.58f);
                        break;
                    case AkIcon.Edit:
                        g.DrawLine(pen, cx - r * 0.62f, cy + r * 0.62f, cx + r * 0.56f, cy - r * 0.56f);
                        g.DrawLine(pen, cx + r * 0.24f, cy - r * 0.74f, cx + r * 0.74f, cy - r * 0.24f);
                        g.DrawLine(pen, cx - r * 0.72f, cy + r * 0.72f, cx - r * 0.34f, cy + r * 0.62f);
                        break;
                    case AkIcon.Undo:
                        g.DrawArc(pen, cx - r * 0.52f, cy - r * 0.34f, r * 1.24f, r * 1.04f, -135, 225);
                        g.DrawLine(pen, cx - r * 0.72f, cy - r * 0.22f, cx - r * 0.28f, cy - r * 0.62f);
                        g.DrawLine(pen, cx - r * 0.72f, cy - r * 0.22f, cx - r * 0.24f, cy + r * 0.10f);
                        break;
                    case AkIcon.ChevLeft:
                        g.DrawLine(pen, cx + r * 0.28f, cy - r * 0.58f, cx - r * 0.34f, cy);
                        g.DrawLine(pen, cx - r * 0.34f, cy, cx + r * 0.28f, cy + r * 0.58f);
                        break;
                    case AkIcon.ChevRight:
                        g.DrawLine(pen, cx - r * 0.28f, cy - r * 0.58f, cx + r * 0.34f, cy);
                        g.DrawLine(pen, cx + r * 0.34f, cy, cx - r * 0.28f, cy + r * 0.58f);
                        break;
                    case AkIcon.Star:
                        System.Drawing.PointF[] sp = new System.Drawing.PointF[10];
                        for (int k = 0; k < 10; k++)
                        {
                            double ang = -System.Math.PI / 2.0 + k * System.Math.PI / 5.0;
                            float rad = (k % 2 == 0) ? r * 0.85f : r * 0.38f;
                            sp[k] = new System.Drawing.PointF(cx + (float)(System.Math.Cos(ang) * rad), cy + (float)(System.Math.Sin(ang) * rad));
                        }
                        g.DrawPolygon(pen, sp);
                        break;
                }
            }
            g.SmoothingMode = oldSm;
        }
    }

    internal sealed class AkButton : System.Windows.Forms.Button
    {
        public AkKind Kind = AkKind.Secondary;
        public AkIcon Icon = AkIcon.None;
        public bool Active = false;
        public bool Dark = true;
        public int Radius = 6;
        private bool _hov = false;
        private bool _down = false;

        public AkButton()
        {
            SetStyle(System.Windows.Forms.ControlStyles.AllPaintingInWmPaint |
                     System.Windows.Forms.ControlStyles.OptimizedDoubleBuffer |
                     System.Windows.Forms.ControlStyles.UserPaint |
                     System.Windows.Forms.ControlStyles.ResizeRedraw, true);
            FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            Cursor = System.Windows.Forms.Cursors.Hand;
            TabStop = false;
            UseMnemonic = false;
        }

        protected override void OnMouseEnter(System.EventArgs e) { _hov = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(System.EventArgs e) { _hov = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(System.Windows.Forms.MouseEventArgs e) { if (e.Button == System.Windows.Forms.MouseButtons.Left) { _down = true; Invalidate(); } base.OnMouseDown(e); }
        protected override void OnMouseUp(System.Windows.Forms.MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }

        protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
        {
            System.Drawing.Graphics g = e.Graphics;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            System.Drawing.Color parentBg = Parent != null ? Parent.BackColor : (Dark ? System.Drawing.Color.FromArgb(29, 31, 32) : System.Drawing.Color.FromArgb(248, 249, 250));
            g.Clear(parentBg);

            System.Drawing.Color accent = Dark ? System.Drawing.Color.FromArgb(252, 150, 31) : System.Drawing.Color.FromArgb(224, 118, 12);
            System.Drawing.Color accentHov = Dark ? System.Drawing.Color.FromArgb(255, 169, 64) : System.Drawing.Color.FromArgb(204, 102, 8);
            System.Drawing.Color surf = Dark ? System.Drawing.Color.FromArgb(39, 41, 43) : System.Drawing.Color.White;
            System.Drawing.Color surfHov = Dark ? System.Drawing.Color.FromArgb(50, 53, 56) : System.Drawing.Color.FromArgb(236, 239, 243);
            System.Drawing.Color border = Dark ? System.Drawing.Color.FromArgb(58, 62, 66) : System.Drawing.Color.FromArgb(210, 216, 224);
            System.Drawing.Color borderHov = Dark ? System.Drawing.Color.FromArgb(84, 89, 95) : System.Drawing.Color.FromArgb(176, 184, 196);
            System.Drawing.Color fgMain = Dark ? System.Drawing.Color.FromArgb(242, 244, 247) : System.Drawing.Color.FromArgb(26, 29, 33);
            System.Drawing.Color fgMuted = Dark ? System.Drawing.Color.FromArgb(154, 160, 168) : System.Drawing.Color.FromArgb(95, 104, 116);
            System.Drawing.Color fgDis = Dark ? System.Drawing.Color.FromArgb(92, 97, 104) : System.Drawing.Color.FromArgb(170, 178, 188);

            bool en = Enabled;
            System.Drawing.Color bg = parentBg;
            System.Drawing.Color bd = System.Drawing.Color.Transparent;
            System.Drawing.Color fg = en ? fgMain : fgDis;
            bool drawFill = false;

            if (Kind == AkKind.Primary)
            {
                drawFill = true;
                bg = en ? (_hov ? accentHov : accent) : (Dark ? System.Drawing.Color.FromArgb(56, 48, 38) : System.Drawing.Color.FromArgb(228, 224, 218));
                fg = en ? (Dark ? System.Drawing.Color.FromArgb(20, 21, 23) : System.Drawing.Color.White) : fgDis;
            }
            else if (Kind == AkKind.AccentOutline)
            {
                drawFill = true;
                bg = en ? (_hov ? (Dark ? System.Drawing.Color.FromArgb(52, 42, 30) : System.Drawing.Color.FromArgb(255, 243, 228)) : surf) : (Dark ? System.Drawing.Color.FromArgb(32, 34, 36) : System.Drawing.Color.FromArgb(244, 246, 248));
                bd = en ? accent : border;
                fg = en ? accent : fgDis;
            }
            else if (Kind == AkKind.Danger)
            {
                drawFill = true;
                System.Drawing.Color red = Dark ? System.Drawing.Color.FromArgb(240, 104, 118) : System.Drawing.Color.FromArgb(196, 40, 56);
                bg = en ? (_hov ? (Dark ? System.Drawing.Color.FromArgb(62, 30, 36) : System.Drawing.Color.FromArgb(254, 228, 231)) : (Dark ? System.Drawing.Color.FromArgb(46, 28, 32) : System.Drawing.Color.FromArgb(255, 240, 242))) : surf;
                bd = en ? (Dark ? System.Drawing.Color.FromArgb(116, 48, 58) : System.Drawing.Color.FromArgb(236, 154, 164)) : border;
                fg = en ? red : fgDis;
            }
            else if (Kind == AkKind.Tab)
            {
                drawFill = _hov && en;
                bg = surfHov;
                fg = en ? (Active ? fgMain : (_hov ? fgMain : fgMuted)) : fgDis;
            }
            else if (Kind == AkKind.Ghost)
            {
                drawFill = (Active || _hov) && en;
                bg = Active ? (Dark ? System.Drawing.Color.FromArgb(52, 42, 30) : System.Drawing.Color.FromArgb(255, 243, 228)) : surfHov;
                bd = Active ? accent : System.Drawing.Color.Transparent;
                fg = en ? (Active ? accent : (_hov ? fgMain : fgMuted)) : fgDis;
            }
            else // Secondary (Ariakit tactile elevated pill)
            {
                drawFill = true;
                bg = en ? (Active ? (Dark ? System.Drawing.Color.FromArgb(52, 42, 30) : System.Drawing.Color.FromArgb(255, 243, 228)) : (_hov ? surfHov : surf)) : (Dark ? System.Drawing.Color.FromArgb(32, 34, 36) : System.Drawing.Color.FromArgb(245, 247, 249));
                bd = en ? (Active ? accent : (_hov ? borderHov : border)) : (Dark ? System.Drawing.Color.FromArgb(44, 47, 50) : System.Drawing.Color.FromArgb(224, 228, 234));
                fg = en ? (Active ? accent : fgMain) : fgDis;
            }

            float ox = 0.5f, oy = (_down && en) ? 1.5f : 0.5f;
            float rw = Width - 1.5f, rh = Height - 1.5f - ((_down && en) ? 1f : 0f);
            if (drawFill || bd.A > 0)
            {
                using (System.Drawing.Drawing2D.GraphicsPath gp = AkDraw.RoundRect(ox, oy, rw, rh, Radius))
                {
                    if (drawFill) using (System.Drawing.SolidBrush br = new System.Drawing.SolidBrush(bg)) g.FillPath(br, gp);
                    if (bd.A > 0) using (System.Drawing.Pen p = new System.Drawing.Pen(bd, 1f)) g.DrawPath(p, gp);
                }
            }
            if (Kind == AkKind.Tab && Active)
            {
                using (System.Drawing.SolidBrush ab = new System.Drawing.SolidBrush(accent))
                    g.FillRectangle(ab, 6, Height - 3, System.Math.Max(8, Width - 12), 2.5f);
            }

            string txt = Text ?? "";
            float yShift = (_down && en) ? 1f : 0f;
            if (Icon != AkIcon.None && txt.Length == 0)
            {
                AkDraw.DrawIcon(g, Icon, Width * 0.5f, Height * 0.5f + yShift, 13.5f, fg);
            }
            else if (Icon != AkIcon.None)
            {
                System.Drawing.Size ts = System.Windows.Forms.TextRenderer.MeasureText(txt, Font, new System.Drawing.Size(Width, Height), System.Windows.Forms.TextFormatFlags.NoPrefix | System.Windows.Forms.TextFormatFlags.NoPadding);
                float iconW = 13f, gap = 6f;
                float totalW = iconW + gap + ts.Width;
                float startX = System.Math.Max(8f, (Width - totalW) * 0.5f);
                AkDraw.DrawIcon(g, Icon, startX + iconW * 0.5f, Height * 0.5f + yShift, 12.5f, fg);
                System.Drawing.Rectangle tr = new System.Drawing.Rectangle((int)(startX + iconW + gap), (int)yShift, System.Math.Max(10, Width - (int)(startX + iconW + gap) - 4), Height);
                System.Windows.Forms.TextRenderer.DrawText(g, txt, Font, tr, fg, System.Windows.Forms.TextFormatFlags.Left | System.Windows.Forms.TextFormatFlags.VerticalCenter | System.Windows.Forms.TextFormatFlags.NoPrefix | System.Windows.Forms.TextFormatFlags.EndEllipsis);
            }
            else
            {
                System.Drawing.Rectangle tr = new System.Drawing.Rectangle(4, (int)yShift, System.Math.Max(8, Width - 8), Height);
                System.Windows.Forms.TextRenderer.DrawText(g, txt, Font, tr, fg, System.Windows.Forms.TextFormatFlags.HorizontalCenter | System.Windows.Forms.TextFormatFlags.VerticalCenter | System.Windows.Forms.TextFormatFlags.NoPrefix | System.Windows.Forms.TextFormatFlags.EndEllipsis);
            }
        }
    }

}
