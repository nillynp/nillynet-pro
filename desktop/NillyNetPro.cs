// ============================================================================
// NillyNet Pro v1.2 — Ultra-Light Native Windows 10/11 Network Monitor,
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
[assembly: AssemblyVersion("1.3.0.0")]
[assembly: AssemblyFileVersion("1.3.0.0")]

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
        private readonly Button _btnTabLive, _btnTabWifi, _btnTabTools, _btnPause, _btnTheme, _btnInfo;
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

        // Tab 1: Full Wi-Fi Analyzer + Nearby Networks + Adapters + Saved Passwords
        private readonly Panel _pnlWifi;
        private readonly DoubleBufferedPanel _wifiCard;
        private readonly SplitContainer _wifiSplit, _botSplit;
        private readonly Button _btnScanWifi, _btnCopyWifi;
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
        private readonly Button _btnPingAll, _btnFlushDns, _btnDnsCf, _btnDnsGgl, _btnDnsAuto, _btnWinNet, _btnNetNote;

        private readonly System.Windows.Forms.Timer _timer;
        private Bitmap _logoBmp;
        private readonly Font _fTitle = new Font("Segoe UI", 10.5f, FontStyle.Bold);
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

            // Responsive Header
            _header = new Panel { Dock = DockStyle.Top, Height = 46 };
            _logoBox = new PictureBox { Size = new Size(26, 26), Location = new Point(12, 10), SizeMode = PictureBoxSizeMode.Zoom, Image = _logoBmp };
            _lblTitle = new Label { Text = "NillyNet Pro", AutoSize = true, Location = new Point(44, 7), Font = _fTitle, UseMnemonic = false };
            _lblSub = new Label { Text = "Ultra-Light Network · Wi-Fi Band/Speed Inspector · 0 MB Idle RAM", AutoSize = true, Location = new Point(45, 25), Font = new Font("Segoe UI", 7.6f), UseMnemonic = false };

            _txtSearch = new TextBox { Width = 200, Height = 26, BorderStyle = BorderStyle.FixedSingle, Font = _fUi };
            if (!string.IsNullOrEmpty(initialFilter)) _txtSearch.Text = initialFilter;
            _txtSearch.TextChanged += delegate { RenderConnections(); };
            _txtSearch.HandleCreated += delegate { Native.SetCue(_txtSearch, "Φίλτρο process / IP (Ctrl+F)..."); };
            _btnPause = MkBtn("||", 34, "Παύση / Συνέχεια ανανέωσης (Space)", delegate { _paused = !_paused; _btnPause.Text = _paused ? "▶" : "||"; });
            _btnTheme = MkBtn("◐", 32, "Αλλαγή Dark / Light θέματος", delegate { _dark = !_dark; ApplyTheme(); });
            _btnInfo = MkBtn("i", 32, "Ultra-Light Specs & Πληροφορίες", delegate { ShowInfoDialog(); });
            _header.Controls.AddRange(new Control[] { _logoBox, _lblTitle, _lblSub, _txtSearch, _btnPause, _btnTheme, _btnInfo });
            _header.Resize += delegate { LayoutHeader(); };

            // Responsive Tab Bar
            _tabBar = new Panel { Dock = DockStyle.Top, Height = 38 };
            _btnTabLive = MkBtn("Ζωντανή Κίνηση && Διεργασίες", 215, "Live Download/Upload + TCP/UDP ανά εφαρμογή", delegate { SwitchTab(0); });
            _btnTabWifi = MkBtn("Wi-Fi Analyzer, Band && Κωδικοί", 225, "Band 2.4/5/6 GHz, Κανάλι, Rx/Tx Mbps, Σήμα dBm, Κοντινά Δίκτυα & Κωδικοί", delegate { SwitchTab(1); });
            _btnTabTools = MkBtn("Ping && 1-Κλικ DNS", 155, "Έλεγχος Ping, Flush DNS & Cloudflare/Google DNS", delegate { SwitchTab(2); });
            _lblLiveRate = new Label { AutoSize = true, Font = _fBold, TextAlign = ContentAlignment.MiddleRight, UseMnemonic = false };
            _tabBar.Controls.AddRange(new Control[] { _btnTabLive, _btnTabWifi, _btnTabTools, _lblLiveRate });
            _tabBar.Resize += delegate { LayoutTabBar(); };

            // ---- Tab 0: Live Traffic & TCP/UDP ----
            _pnlLive = new Panel { Dock = DockStyle.Fill };
            _graphPanel = new DoubleBufferedPanel { Dock = DockStyle.Top, Height = 122 };
            _graphPanel.Paint += GraphPanel_Paint;
            _lvConns = BuildLV(new string[] { "Εφαρμογή (Process)", "PID", "Proto", "Τοπική Διεύθυνση", "Απομακρυσμένη IP:Port", "Κατάσταση" },
                               new int[] { 220, 68, 58, 200, 260, 140 });
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
            _btnScanWifi = MkBtn("↻ Σάρωση Wi-Fi", 132, "Επανασάρωση Wi-Fi Band, Σήματος & Κοντινών Δικτύων (On-Demand · 0% idle)", delegate { RefreshWifiTabAsync(); });
            _btnScanWifi.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _wifiCard.Controls.Add(_btnScanWifi);
            _wifiCard.Resize += delegate { _btnScanWifi.Location = new Point(Math.Max(10, _wifiCard.Width - _btnScanWifi.Width - 12), 10); _wifiCard.Invalidate(); };

            _wifiSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterWidth = 5 };

            // Top split: Nearby Wi-Fi Networks (Band, Channel, Signal dBm, Standard)
            Panel pNear = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 6, 0, 0) };
            Label lblNear = new Label { Text = "ΚΟΝΤΙΝΑ ΔΙΚΤΥΑ WI-FI & ΚΑΝΑΛΙΑ (Band 2.4 / 5 / 6 GHz · Σήμα dBm · Πρότυπο)", Dock = DockStyle.Top, Height = 22, Font = _fBold, UseMnemonic = false };
            _lvNearby = BuildLV(new string[] { "Όνομα Wi-Fi (SSID)", "Band", "Κανάλι", "Σήμα / dBm", "Πρότυπο Wi-Fi", "Ασφάλεια", "BSSID (MAC)" },
                                new int[] { 220, 72, 64, 120, 155, 130, 145 });
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
            _btnCopyWifi = MkBtn("Αντιγραφή Κωδικού", 155, "Αντιγραφή κωδικού Wi-Fi στο πρόχειρο", delegate
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
            _btnPingAll = MkBtn("▶ Ping Test (CF/Google/Host)", 205, "Μέτρηση ms σε 1.1.1.1, 8.8.8.8 & custom host", delegate { RunPingAsync(); });
            _btnFlushDns = MkBtn("Flush DNS", 100, "Καθαρισμός DNS cache", delegate { RunFlushDns(); });
            _btnDnsCf = MkBtn("DNS 1.1.1.1 (Cloudflare)", 170, "Cloudflare γρήγορο DNS", delegate { ApplyDns("1.1.1.1", "1.0.0.1"); });
            _btnDnsGgl = MkBtn("DNS 8.8.8.8 (Google)", 150, "Google DNS", delegate { ApplyDns("8.8.8.8", "8.8.4.4"); });
            _btnDnsAuto = MkBtn("Αυτόματο DNS", 115, "Επαναφορά DHCP DNS", delegate { ApplyDns(null, null); });
            _btnWinNet = MkBtn("Ρυθμίσεις Win", 110, "Άνοιγμα Windows Network Settings", delegate { OpenUrl("ms-settings:network"); });
            _btnNetNote = MkBtn("↗ Αναφορά σε NillyNote", 168, "Αποστολή πλήρους αναφοράς Δικτύου/Wi-Fi/Ping σε NillyNote Pro", delegate { SendReportToNillyNote(); });
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
            _statusBar = new Panel { Dock = DockStyle.Bottom, Height = 26, Padding = new Padding(10, 0, 10, 0) };
            _lblStatus = new Label { Dock = DockStyle.Fill, Font = _fSmall, TextAlign = ContentAlignment.MiddleLeft, UseMnemonic = false };
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
            _timer.Tick += delegate { if (!_paused) SampleNetwork(); };

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

        private Button MkBtn(string txt, int w, string tip, EventHandler click)
        {
            Button b = new Button
            {
                Text = txt, Width = w, Height = 28, FlatStyle = FlatStyle.Flat, Font = _fBold,
                Cursor = Cursors.Hand, Margin = new Padding(0, 0, 6, 4), TabStop = false
            };
            b.FlatAppearance.BorderSize = 1;
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
            int pad = 10, gap = 5;
            int rx = w - pad;
            rx -= _btnInfo.Width; _btnInfo.Location = new Point(rx, 9); rx -= gap;
            rx -= _btnTheme.Width; _btnTheme.Location = new Point(rx, 9); rx -= gap;
            rx -= _btnPause.Width; _btnPause.Location = new Point(rx, 9); rx -= gap;
            int availSearch = rx - 355;
            if (availSearch >= 135)
            {
                if (_header.Height != 46) _header.Height = 46;
                int sw = Math.Min(230, availSearch);
                _txtSearch.SetBounds(rx - sw, 10, sw, 26);
            }
            else
            {
                if (_header.Height != 80) _header.Height = 80;
                _txtSearch.SetBounds(pad, 48, Math.Max(140, w - pad * 2), 26);
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
                _bgMain = Color.FromArgb(24, 26, 31); _bgPanel = Color.FromArgb(31, 34, 41);
                _bgSurf = Color.FromArgb(39, 43, 52); _bgHover = Color.FromArgb(49, 54, 66);
                _bgSel = Color.FromArgb(54, 67, 89); _bgAlt = Color.FromArgb(28, 30, 36);
                _border = Color.FromArgb(52, 57, 68); _fgMain = Color.FromArgb(236, 239, 244);
                _fgMuted = Color.FromArgb(148, 157, 174); _accent = Color.FromArgb(252, 150, 31);
                _cyan = Color.FromArgb(102, 217, 239); _green = Color.FromArgb(166, 226, 46);
                _pink = Color.FromArgb(249, 38, 114);
            }
            else
            {
                _bgMain = Color.FromArgb(248, 249, 251); _bgPanel = Color.FromArgb(238, 241, 246);
                _bgSurf = Color.White; _bgHover = Color.FromArgb(226, 232, 242);
                _bgSel = Color.FromArgb(209, 228, 250); _bgAlt = Color.FromArgb(243, 245, 249);
                _border = Color.FromArgb(210, 216, 226); _fgMain = Color.FromArgb(28, 32, 40);
                _fgMuted = Color.FromArgb(98, 108, 125); _accent = Color.FromArgb(224, 118, 12);
                _cyan = Color.FromArgb(14, 132, 168); _green = Color.FromArgb(62, 145, 32);
                _pink = Color.FromArgb(204, 28, 92);
            }

            Native.SetDarkTitlebar(Handle, _dark);
            BackColor = _bgMain; ForeColor = _fgMain;
            _header.BackColor = _bgPanel; _tabBar.BackColor = _bgPanel; _statusBar.BackColor = _bgPanel;
            _pnlLive.BackColor = _bgMain; _pnlWifi.BackColor = _bgMain; _pnlTools.BackColor = _bgMain;
            _graphPanel.BackColor = _bgPanel; _wifiCard.BackColor = _bgPanel;
            _lblTitle.ForeColor = _fgMain; _lblSub.ForeColor = _accent; _lblStatus.ForeColor = _fgMuted; _lblLiveRate.ForeColor = _cyan;
            _lnkBrand.LinkColor = _fgMuted; _lnkBrand.ActiveLinkColor = _accent;
            _txtSearch.BackColor = _bgSurf; _txtSearch.ForeColor = _fgMain;
            _txtPingHost.BackColor = _bgSurf; _txtPingHost.ForeColor = _fgMain;
            _txtToolLog.BackColor = _bgSurf; _txtToolLog.ForeColor = _fgMain;
            _lstWifi.BackColor = _bgSurf; _lstWifi.ForeColor = _fgMain;
            _lblWifiKey.ForeColor = _accent;

            DoubleBufferedLV[] lvs = new DoubleBufferedLV[] { _lvConns, _lvNearby, _lvAdapters };
            for (int i = 0; i < lvs.Length; i++)
            {
                lvs[i].BackColor = _bgMain; lvs[i].ForeColor = _fgMain;
                Native.SetDarkScrollbars(lvs[i], _dark); lvs[i].Invalidate();
            }
            _graphPanel.Invalidate();
            _wifiCard.Invalidate();
            StyleButtons();
        }

        private void StyleButtons()
        {
            StyleBtn(_btnPause, false, _accent);
            StyleBtn(_btnTheme, false, _accent);
            StyleBtn(_btnInfo, false, _accent);
            _btnInfo.ForeColor = _accent; _btnInfo.FlatAppearance.BorderColor = _accent;

            StyleBtn(_btnTabLive, _activeTab == 0, _cyan);
            StyleBtn(_btnTabWifi, _activeTab == 1, _accent);
            StyleBtn(_btnTabTools, _activeTab == 2, _green);

            StyleBtn(_btnScanWifi, true, _cyan);
            StyleBtn(_btnCopyWifi, true, _accent);
            StyleBtn(_btnPingAll, true, _green);
            StyleBtn(_btnFlushDns, false, _cyan);
            StyleBtn(_btnDnsCf, false, _accent);
            StyleBtn(_btnDnsGgl, false, _cyan);
            StyleBtn(_btnDnsAuto, false, _fgMuted);
            StyleBtn(_btnWinNet, false, _fgMuted);
            StyleBtn(_btnNetNote, false, _accent);
            _btnNetNote.ForeColor = _accent; _btnNetNote.FlatAppearance.BorderColor = _accent;
        }

        private void StyleBtn(Button b, bool primary, Color accent)
        {
            b.BackColor = primary ? accent : _bgSurf;
            b.ForeColor = primary ? Color.FromArgb(20, 22, 26) : _fgMain;
            b.FlatAppearance.BorderColor = primary ? accent : _border;
            b.FlatAppearance.MouseOverBackColor = primary ? accent : _bgHover;
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

        private void PopulateWifiTabUi(List<string> profs)
        {
            _wifiCard.Invalidate();

            // Nearby Wi-Fi table
            _lvNearby.BeginUpdate();
            _lvNearby.Items.Clear();
            for (int i = 0; i < _nearbyWifi.Count; i++)
            {
                NearbyWifi n = _nearbyWifi[i];
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
                TextRenderer.DrawText(g, string.Format("📶  {0}   ·   {1}   ·   {2}", wf.Ssid, wf.Band, wf.WifiGen),
                    new Font("Segoe UI", 11.2f, FontStyle.Bold), new Rectangle(14, 10, rightLimit - 14, 24), _fgMain, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

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
                TextRenderer.DrawText(g, hdr, new Font("Segoe UI", 10.5f, FontStyle.Bold),
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
            _lvConns.BeginUpdate();
            _lvConns.Items.Clear();
            int max = 350;
            for (int i = 0; i < _allConns.Count && _lvConns.Items.Count < max; i++)
            {
                NetConn c = _allConns[i];
                if (q.Length > 0 && c.Norm.IndexOf(q, StringComparison.Ordinal) < 0) continue;
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
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "NillyNet Pro"); }
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
                Label hdr = new Label { Text = "NillyNet Pro v1.1", Location = new Point(70, 16), AutoSize = true, Font = new Font("Segoe UI", 13.0f, FontStyle.Bold) };
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
            if (disposing) { if (_timer != null) _timer.Dispose(); if (_logoBmp != null) _logoBmp.Dispose(); _tip.Dispose(); }
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

            Application.Run(new MainForm(false, initFilter));
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
}
