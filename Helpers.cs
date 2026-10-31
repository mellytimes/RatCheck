using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace RatCheck;

internal sealed record SigInfo(bool Exists, bool Valid, string Signer);

// ------------------------------------------------------------------ digital signatures
internal static class Sig
{
    private static readonly Dictionary<string, SigInfo> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object Gate = new();

    public static SigInfo Get(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return new SigInfo(false, false, "");
        lock (Gate)
        {
            if (Cache.TryGetValue(path, out var hit)) return hit;
        }

        SigInfo info;
        try
        {
            if (!File.Exists(path))
                info = new SigInfo(false, false, "");
            else if (WinTrust.VerifyEmbedded(path) == 0)
                info = new SigInfo(true, true, SignerName(path));
            else if (WinTrust.IsInCatalog(path))
                info = new SigInfo(true, true, "Microsoft Windows (catalog)");
            else
                info = new SigInfo(true, false, "");
        }
        catch
        {
            info = new SigInfo(File.Exists(path), false, "");
        }

        lock (Gate) Cache[path] = info;
        return info;
    }

    private static string SignerName(string path)
    {
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch
        {
            return "unknown signer";
        }
    }
}

internal static class WinTrust
{
    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, IntPtr data);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
        string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile,
        ref uint pcbHash, [Out] byte[] pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash,
        uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    /// <summary>Checks the file's own (embedded) Authenticode signature. 0 = valid.</summary>
    public static int VerifyEmbedded(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path
        };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        IntPtr pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        Marshal.StructureToPtr(fileInfo, pFile, false);
        try
        {
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = 0,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            Marshal.StructureToPtr(data, pData, false);
            Guid action = ActionGenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, pData);

            data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, false);
            WinVerifyTrust(IntPtr.Zero, ref action, pData);
            return result;
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
            Marshal.FreeHGlobal(pData);
        }
    }

    /// <summary>Most Windows system files are signed through catalog files instead of embedded signatures.</summary>
    public static bool IsInCatalog(string path)
    {
        foreach (var alg in new[] { "SHA256", "SHA1" })
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                uint size = 64;
                var hash = new byte[64];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle.DangerousGetHandle(), ref size, hash, 0))
                    continue;
                IntPtr cat = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                if (cat != IntPtr.Zero)
                {
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                    return true;
                }
            }
            catch
            {
                // file locked / unreadable - treat as not in catalog
            }
            finally
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }
        return false;
    }
}

// ------------------------------------------------------------------ paths
internal static class Paths
{
    public static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    // Folders any program (including malware) can write to without admin rights.
    private static readonly string[] HighRiskDirs =
    {
        @"\AppData\Local\Temp\", @"\Windows\Temp\", @"\Users\Public\", @"\$Recycle.Bin\", @"\Windows\Tasks\",
        @"\Windows\debug\", @"\PerfLogs\", @"\Windows\Fonts\", @"\System Volume Information\"
    };
    private static readonly string[] MediumRiskDirs =
    {
        @"\AppData\Roaming\", @"\ProgramData\", @"\Downloads\", @"\AppData\LocalLow\", @"\Desktop\"
    };

    private static readonly Regex DriveRootExe = new(@"^[a-z]:\\[^\\]+\.(exe|dll|scr)$", RegexOptions.IgnoreCase);
    private static readonly Regex ExeInCommand = new(
        @"^(.+?\.(exe|com|bat|cmd|vbs|vbe|js|jse|wsf|ps1|scr|dll|hta|pif|lnk|cpl))(?=\s|,|$)", RegexOptions.IgnoreCase);

    /// <returns>"High", "Medium" or "None"</returns>
    public static string Risk(string path)
    {
        if (string.IsNullOrEmpty(path)) return "None";
        foreach (var d in HighRiskDirs)
            if (path.Contains(d, StringComparison.OrdinalIgnoreCase)) return "High";
        foreach (var d in MediumRiskDirs)
            if (path.Contains(d, StringComparison.OrdinalIgnoreCase)) return "Medium";
        if (DriveRootExe.IsMatch(path)) return "Medium";
        return "None";
    }

    /// <summary>Pulls the program path out of a command line like  "C:\x\a.exe" -arg  or  C:\x\a.exe /b</summary>
    public static string ResolveExe(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var c = Environment.ExpandEnvironmentVariables(command.Trim());
        if (c.StartsWith(@"\??\")) c = c.Substring(4);
        if (c.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) c = WinDir + c.Substring(11);
        else if (c.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) c = Path.Combine(WinDir, c);

        string p;
        if (c.StartsWith('"'))
        {
            int end = c.IndexOf('"', 1);
            p = end > 1 ? c.Substring(1, end - 1) : c.Trim('"');
        }
        else
        {
            var m = ExeInCommand.Match(c);
            p = m.Success ? m.Groups[1].Value : c.Split((char[])null, StringSplitOptions.RemoveEmptyEntries)[0];
        }

        if (!p.Contains('\\')) p = FindOnPath(p) ?? p;
        return p;
    }

    private static string FindOnPath(string name)
    {
        var names = Path.HasExtension(name) ? new[] { name } : new[] { name + ".exe", name };
        var dirs = new List<string> { Path.Combine(WinDir, "System32"), WinDir };
        dirs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries));
        foreach (var dir in dirs)
        {
            foreach (var n in names)
            {
                try
                {
                    var full = Path.Combine(dir.Trim(), n);
                    if (File.Exists(full)) return full;
                }
                catch
                {
                    // bad PATH entry
                }
            }
        }
        return null;
    }
}

// ------------------------------------------------------------------ registry
internal static class Reg
{
    public static RegistryKey Open(RegistryHive hive, string sub)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            return root.OpenSubKey(sub);
        }
        catch
        {
            return null;
        }
    }

    public static object Val(RegistryHive hive, string sub, string name)
    {
        try
        {
            using var k = Open(hive, sub);
            return k?.GetValue(name);
        }
        catch
        {
            return null;
        }
    }

    public static string Str(RegistryHive hive, string sub, string name) => Val(hive, sub, name)?.ToString();

    public static int? Int(RegistryHive hive, string sub, string name) => Val(hive, sub, name) is int i ? i : null;
}

// ------------------------------------------------------------------ WMI
internal static class Wmi
{
    public static List<ManagementBaseObject> Query(string ns, string wql)
    {
        var list = new List<ManagementBaseObject>();
        try
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(wql));
            foreach (ManagementBaseObject o in searcher.Get()) list.Add(o);
        }
        catch
        {
            // namespace missing / access denied
        }
        return list;
    }

    public static T Get<T>(ManagementBaseObject o, string prop)
    {
        try
        {
            var v = o?[prop];
            return v == null ? default : (T)Convert.ChangeType(v, typeof(T));
        }
        catch
        {
            return default;
        }
    }

    public static string Str(ManagementBaseObject o, string prop)
    {
        try { return o?[prop]?.ToString(); }
        catch { return null; }
    }

    public static string[] Arr(ManagementBaseObject o, string prop)
    {
        try { return o?[prop] as string[] ?? Array.Empty<string>(); }
        catch { return Array.Empty<string>(); }
    }

    public static DateTime Time(ManagementBaseObject o, string prop)
    {
        try
        {
            var s = Str(o, prop);
            return string.IsNullOrEmpty(s) ? DateTime.MinValue : ManagementDateTimeConverter.ToDateTime(s);
        }
        catch
        {
            return DateTime.MinValue;
        }
    }
}

// ------------------------------------------------------------------ native UI helpers
internal static class NativeUi
{
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);

    public static void DarkTitleBar(IntPtr hwnd)
    {
        try
        {
            int on = 1;
            if (DwmSetWindowAttribute(hwnd, 20, ref on, 4) != 0) DwmSetWindowAttribute(hwnd, 19, ref on, 4);
        }
        catch { }
    }

    public static void DarkScrollbars(IntPtr hwnd)
    {
        try { SetWindowTheme(hwnd, "DarkMode_Explorer", null); }
        catch { }
    }
}
