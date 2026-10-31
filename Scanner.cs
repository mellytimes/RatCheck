using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;

namespace RatCheck;

internal enum Tone { Text, Dim, Bright, Section, High, Medium, Low, Ok, Warn, Border }

internal sealed record Finding(string Severity, string Category, string Message);

/// <summary>All the checks. Read-only: nothing on the PC is changed.</summary>
internal sealed class Scanner
{
    private const string H = "HIGH", M = "MEDIUM", L = "LOW", I = "INFO";
    private const string DefenderNs = @"root\Microsoft\Windows\Defender";
    private const RegistryHive LM = RegistryHive.LocalMachine;
    private const RegistryHive CU = RegistryHive.CurrentUser;

    public event Action<string, Tone> Line;
    public event Action<string> Status;
    public event Action<Finding> Found;

    public readonly List<Finding> Findings = new();
    private readonly bool isAdmin;
    private readonly string winDir = Paths.WinDir;
    private readonly DateTime since = DateTime.Now.AddDays(-30);
    private List<ProcInfo> procs;
    private int sectionStart;

    private sealed record ProcInfo(uint Pid, string Name, string ExePath, string CommandLine);

    public Scanner(bool isAdmin) => this.isAdmin = isAdmin;

    public static readonly (string Label, Action<Scanner> Run)[] Checks =
    {
        ("1   User startup (HKCU)",        s => s.UserStartup()),
        ("2   Machine startup (HKLM)",     s => s.MachineStartup()),
        ("3   Automatic services",         s => s.AutoServices()),
        ("4   Running processes",          s => s.Processes()),
        ("5   Process paths & signatures", s => s.ProcessPaths()),
        ("6   Defender status",            s => s.Defender()),
        ("7   Threat history",             s => s.ThreatHistory()),
        ("8   Local users",                s => s.LocalUsers()),
        ("9   Scheduled tasks",            s => s.ScheduledTasks()),
        ("10  Network connections",        s => s.Network()),
        ("11  Hijack / persistence spots", s => s.Hijacks()),
        ("12  Remote access & firewall",   s => s.RemoteAccess()),
        ("13  Recently dropped files",     s => s.DroppedFiles()),
    };

    // ================================================================ output
    public void Out(string text = "", Tone tone = Tone.Text) => Line?.Invoke(text, tone);
    private void Info(string text) => Out("  - " + text, Tone.Dim);

    private void Section(string title)
    {
        Out();
        Out(new string('-', 78), Tone.Border);
        Out("  " + title, Tone.Section);
        Out(new string('-', 78), Tone.Border);
        sectionStart = Findings.Count;
        Status?.Invoke(title);
    }

    private void Close()
    {
        if (Findings.Count == sectionStart) Out("  [OK] Nothing suspicious found here.", Tone.Ok);
    }

    private void Add(string severity, string category, string message)
    {
        var f = new Finding(severity, category, message);
        Findings.Add(f);
        var tone = severity switch { H => Tone.High, M => Tone.Medium, L => Tone.Low, _ => Tone.Dim };
        Out($"  [{severity}] {message}", tone);
        Found?.Invoke(f);
    }

    public void Header(string title)
    {
        Out($"  RatCheck  -  {title}", Tone.Bright);
        Out($"  {DateTime.Now:yyyy-MM-dd HH:mm}   Computer: {Environment.MachineName}   User: {Environment.UserName}   Admin: {isAdmin}", Tone.Dim);
    }

    // ================================================================ shared logic
    private static readonly Regex[] Lolbins =
    {
        new(@"powershell(\.exe)?.*\s-(e|ec|enc|enco|encodedcommand)\s", RegexOptions.IgnoreCase),
        new(@"powershell(\.exe)?.*(-w(indowstyle)?\s+h(idden)?\b|\biex\b|invoke-expression|downloadstring|downloadfile|frombase64string|invoke-webrequest|\biwr\b)", RegexOptions.IgnoreCase),
        new(@"\bmshta(\.exe)?\b", RegexOptions.IgnoreCase),
        new(@"\b(wscript|cscript)(\.exe)?\b", RegexOptions.IgnoreCase),
        new(@"regsvr32(\.exe)?.*(/i:|scrobj)", RegexOptions.IgnoreCase),
        new(@"rundll32(\.exe)?.*(javascript:|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\[^\\]+\.dll)", RegexOptions.IgnoreCase),
        new(@"certutil(\.exe)?.*(-urlcache|-decode)", RegexOptions.IgnoreCase),
        new(@"bitsadmin(\.exe)?.*/transfer", RegexOptions.IgnoreCase),
        new(@"cmd(\.exe)?\s+/c.*(http|powershell|start\s+/b|\^)", RegexOptions.IgnoreCase),
    };

    private void TestEntry(string category, string name, string command, bool quietMissing = false, bool onlyRiskyPaths = false)
    {
        command ??= "";
        if (Lolbins.Any(r => r.IsMatch(command)))
        {
            Add(H, category, $"{name} -> launched via script/LOLBin: {command}");
            return;
        }

        var exe = Paths.ResolveExe(command);
        if (string.IsNullOrEmpty(exe)) return;
        var sig = Sig.Get(exe);
        var risk = Paths.Risk(exe);
        var who = sig.Valid ? "signed by " + sig.Signer : "UNSIGNED";

        if (!sig.Exists)
        {
            if (!quietMissing) Add(L, category, $"{name} -> target file missing (leftover entry?): {exe}");
            return;
        }
        if (risk == "High")
        {
            if (sig.Valid) Add(L, category, $"{name} -> runs from a temp/public folder ({who}): {exe}");
            else Add(H, category, $"{name} -> UNSIGNED file in a temp/public folder: {exe}");
            return;
        }
        if (risk == "Medium" && !sig.Valid)
        {
            Add(M, category, $"{name} -> unsigned file in a user-writable folder: {exe}");
            return;
        }
        if (!sig.Valid && !onlyRiskyPaths)
            Add(L, category, $"{name} -> unsigned: {exe}");
    }

    private static IEnumerable<(string Name, string Command)> RunEntries(RegistryHive hive, params string[] subKeys)
    {
        foreach (var sub in subKeys)
        {
            using var key = Reg.Open(hive, sub);
            if (key == null) continue;
            foreach (var n in key.GetValueNames())
            {
                if (string.IsNullOrEmpty(n)) continue; // (Default)
                yield return (n, key.GetValue(n)?.ToString() ?? "");
            }
        }
    }

    private static IEnumerable<(string Name, string Command)> StartupFolder(string folder)
    {
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) yield break;
        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var name = Path.GetFileName(file);
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            var cmd = "\"" + file + "\"";
            if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                var target = ResolveShortcut(file);
                if (!string.IsNullOrEmpty(target)) cmd = target;
            }
            yield return (name, cmd);
        }
    }

    private static string ResolveShortcut(string lnk)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            dynamic shell = Activator.CreateInstance(type);
            dynamic sc = shell.CreateShortcut(lnk);
            string target = sc.TargetPath;
            string args = sc.Arguments;
            return string.IsNullOrEmpty(target) ? null : $"\"{target}\" {args}".Trim();
        }
        catch
        {
            return null;
        }
    }

    private List<ProcInfo> Procs()
    {
        if (procs != null) return procs;
        procs = Wmi.Query(@"root\cimv2", "SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process")
            .Select(o => new ProcInfo(Wmi.Get<uint>(o, "ProcessId"), Wmi.Str(o, "Name") ?? "",
                                      Wmi.Str(o, "ExecutablePath"), Wmi.Str(o, "CommandLine")))
            .ToList();
        return procs;
    }

    // ================================================================ 1. user startup
    private void UserStartup()
    {
        Section("1. Registry startup entries (current user)");
        var entries = RunEntries(CU,
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
            .Concat(StartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup)))
            .ToList();
        if (entries.Count == 0) Info("No entries.");
        foreach (var (name, cmd) in entries)
        {
            Info($"{name} = {cmd}");
            TestEntry("Startup (user)", name, cmd);
        }
        Close();
    }

    // ================================================================ 2. machine startup
    private void MachineStartup()
    {
        Section("2. Machine-wide startup entries (all users)");
        var entries = RunEntries(LM,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
            .Concat(StartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)))
            .ToList();
        if (entries.Count == 0) Info("No entries.");
        foreach (var (name, cmd) in entries)
        {
            Info($"{name} = {cmd}");
            TestEntry("Startup (machine)", name, cmd);
        }
        Close();
    }

    // ================================================================ 3. services
    private void AutoServices()
    {
        Section("3. Automatic services");
        var services = Wmi.Query(@"root\cimv2", "SELECT Name, State, PathName FROM Win32_Service WHERE StartMode='Auto'");
        Out($"  {services.Count} auto-start services. Non-Microsoft ones are listed for review:");
        foreach (var s in services)
        {
            var name = Wmi.Str(s, "Name");
            var pathName = Wmi.Str(s, "PathName");
            var label = $"{name} [{Wmi.Str(s, "State")}]";
            var exe = Paths.ResolveExe(pathName);

            if (exe != null && exe.EndsWith(@"\svchost.exe", StringComparison.OrdinalIgnoreCase))
            {
                // svchost services load a DLL - that DLL is what matters
                var dll = Reg.Str(LM, $@"SYSTEM\CurrentControlSet\Services\{name}\Parameters", "ServiceDll");
                if (!string.IsNullOrEmpty(dll))
                    TestEntry("Services", label + " (ServiceDll)", "\"" + Environment.ExpandEnvironmentVariables(dll) + "\"", quietMissing: true);
                continue;
            }

            var sig = Sig.Get(exe);
            if (!(sig.Valid && sig.Signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)))
                Info($"{label,-42} {pathName}");
            TestEntry("Services", label, pathName, quietMissing: true);
        }
        Close();
    }

    // ================================================================ 4. processes
    private static readonly HashSet<string> System32Procs = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
        "taskhostw.exe", "dllhost.exe", "conhost.exe", "spoolsv.exe", "rundll32.exe", "dwm.exe", "sihost.exe",
        "ctfmon.exe", "runtimebroker.exe", "lsaiso.exe", "fontdrvhost.exe", "searchindexer.exe", "wmiprvse.exe"
    };

    private static readonly Regex TypoNames = new(
        @"^(scvhost|svch0st|svhost|svchosts|svchost32|lsas|lsasss|isass|lssas|csrs|cssrs|crss|winl0gon|winlogin|expl0rer|exploer|explorer32|dllhst|taskhost32|rundl32|rundll|smss32|services32|spoolsvc)\.exe$",
        RegexOptions.IgnoreCase);

    private static readonly Regex RemoteTools = new(
        @"^(anydesk|teamviewer|rustdesk|ultraviewer|screenconnect|connectwise|splashtop|radmin|ammyy|aa_v3|rutserv|rfusclient|netsupport|client32|dwagent|dwrcs|winvnc|tvnserver|vncserver|remoting_host|remotepc|parsecd|meshagent|atera|syncro|simplehelp|zohoassist|logmein|supremo|getscreen)",
        RegexOptions.IgnoreCase);

    private void Processes()
    {
        Section("4. Running processes");
        var list = Procs();
        Out($"  {list.Count} processes running.");
        var myPid = (uint)Environment.ProcessId;
        var sys32 = Path.Combine(winDir, "System32");
        var wow64 = Path.Combine(winDir, "SysWOW64");

        foreach (var p in list)
        {
            if (p.Pid == myPid) continue;
            var id = $"{p.Name} (PID {p.Pid})";

            if (TypoNames.IsMatch(p.Name))
                Add(H, "Processes", $"{id} -> name imitates a Windows process: {p.ExePath}");

            if (!string.IsNullOrEmpty(p.ExePath))
            {
                var dir = Path.GetDirectoryName(p.ExePath) ?? "";
                bool wrongFolder =
                    (System32Procs.Contains(p.Name) &&
                     !dir.Equals(sys32, StringComparison.OrdinalIgnoreCase) &&
                     !dir.Equals(wow64, StringComparison.OrdinalIgnoreCase)) ||
                    (p.Name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                     !dir.Equals(winDir, StringComparison.OrdinalIgnoreCase));
                if (wrongFolder)
                    Add(H, "Processes", $"{id} -> Windows process name running from the WRONG folder: {p.ExePath}");

                if (!File.Exists(p.ExePath))
                    Add(M, "Processes", $"{id} -> its executable was deleted from disk while running: {p.ExePath}");
            }

            if (RemoteTools.IsMatch(p.Name))
                Add(M, "Processes", $"{id} -> remote-access tool running (fine ONLY if you installed it): {p.ExePath}");

            if (!string.IsNullOrEmpty(p.CommandLine) && Lolbins.Any(r => r.IsMatch(p.CommandLine)))
                Add(H, "Processes", $"{id} -> suspicious command line: {p.CommandLine}");
        }
        Close();
    }

    // ================================================================ 5. process paths
    private void ProcessPaths()
    {
        Section("5. Process path & signature check");
        Out("  Checking digital signatures of every running program (may take a minute)...", Tone.Dim);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Procs())
        {
            if (string.IsNullOrEmpty(p.ExePath) || !seen.Add(p.ExePath)) continue;
            TestEntry("Process path", $"{p.Name} (PID {p.Pid})", "\"" + p.ExePath + "\"", quietMissing: true, onlyRiskyPaths: true);
        }
        Out($"  {seen.Count} unique program paths checked.", Tone.Dim);
        Close();
    }

    // ================================================================ 6. defender
    private void Defender()
    {
        Section("6. Microsoft Defender status");
        foreach (var av in Wmi.Query(@"root\SecurityCenter2", "SELECT displayName FROM AntiVirusProduct"))
            Info("Registered antivirus: " + Wmi.Str(av, "displayName"));

        var st = Wmi.Query(DefenderNs, "SELECT * FROM MSFT_MpComputerStatus").FirstOrDefault();
        if (st == null)
        {
            Add(H, "Defender", "Could not read Defender status (service stopped/removed?). Normal ONLY if you use another antivirus.");
        }
        else
        {
            var mode = Wmi.Str(st, "AMRunningMode") ?? "";
            bool passive = Regex.IsMatch(mode, "Passive|SxS|EDR", RegexOptions.IgnoreCase);
            Info($"Mode: {mode} | Signatures: {Wmi.Str(st, "AntivirusSignatureVersion")} (age {Wmi.Get<long>(st, "AntivirusSignatureAge")} day(s))");

            var checks = new (string Prop, string Label)[]
            {
                ("AMServiceEnabled", "Defender service"),
                ("AntivirusEnabled", "Antivirus"),
                ("RealTimeProtectionEnabled", "Real-time protection"),
                ("BehaviorMonitorEnabled", "Behavior monitoring"),
                ("IoavProtectionEnabled", "Download/attachment scanning"),
                ("OnAccessProtectionEnabled", "On-access protection"),
                ("IsTamperProtected", "Tamper protection"),
            };
            foreach (var (prop, label) in checks)
            {
                if (Wmi.Get<bool>(st, prop)) Out($"  [ON] {label}", Tone.Ok);
                else if (passive) Info($"{label} is OFF (Defender is passive - another antivirus is in charge)");
                else Add(prop == "IsTamperProtected" ? M : H, "Defender", $"{label} is OFF");
            }

            long sigAge = Wmi.Get<long>(st, "AntivirusSignatureAge");
            if (sigAge > 7) Add(M, "Defender", $"Signatures are {sigAge} days old (malware often blocks updates)");
            if (Wmi.Get<long>(st, "QuickScanAge") > 30 && Wmi.Get<long>(st, "FullScanAge") > 30)
                Add(L, "Defender", "No scan has run in the last 30 days");
        }

        // Policy keys that malware sets to kill Defender
        const string pol = @"SOFTWARE\Policies\Microsoft\Windows Defender";
        if (Reg.Int(LM, pol, "DisableAntiSpyware") == 1 || Reg.Int(LM, pol, "DisableAntiVirus") == 1)
            Add(H, "Defender", "Policy registry value disables Defender (classic malware trick)");
        foreach (var n in new[] { "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableOnAccessProtection", "DisableIOAVProtection", "DisableScanOnRealtimeEnable" })
            if (Reg.Int(LM, pol + @"\Real-Time Protection", n) == 1)
                Add(H, "Defender", $"Policy '{n}' is set to 1");

        // Exclusions - RATs add themselves here so Defender ignores them
        var pref = Wmi.Query(DefenderNs, "SELECT * FROM MSFT_MpPreference").FirstOrDefault();
        if (pref != null)
        {
            bool needAdmin = false;
            var lists = new (string Type, string Prop)[]
            {
                ("Path", "ExclusionPath"), ("Process", "ExclusionProcess"),
                ("Extension", "ExclusionExtension"), ("IP", "ExclusionIpAddress")
            };
            foreach (var (type, prop) in lists)
            {
                foreach (var v in Wmi.Arr(pref, prop))
                {
                    if (string.IsNullOrWhiteSpace(v)) continue;
                    if (v.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)) { needAdmin = true; continue; }
                    bool high = Regex.IsMatch(v, @"^[a-z]:\\?$", RegexOptions.IgnoreCase) ||
                                Regex.IsMatch(v, @"^\.?(exe|dll|ps1|vbs|js|bat|scr)$", RegexOptions.IgnoreCase) ||
                                Paths.Risk(v.TrimEnd('\\') + "\\") != "None";
                    Add(high ? H : M, "Defender", $"Exclusion ({type}): {v}   <- did YOU add this?");
                }
            }
            if (needAdmin) Out("  (Run as Administrator to see Defender exclusions.)", Tone.Warn);
        }

        // Defender event log: protection turned off / exclusions changed
        try
        {
            long ms = 30L * 24 * 3600 * 1000;
            var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName,
                $"*[System[(EventID=5001 or EventID=5010 or EventID=5012 or EventID=5007) and TimeCreated[timediff(@SystemTime) <= {ms}]]]")
            {
                ReverseDirection = true
            };
            using var reader = new EventLogReader(query);
            int shown = 0, read = 0;
            for (var e = reader.ReadEvent(); e != null && shown < 10 && read < 2000; e = reader.ReadEvent(), read++)
            {
                using (e)
                {
                    var t = e.TimeCreated?.ToString("yyyy-MM-dd HH:mm") ?? "?";
                    switch (e.Id)
                    {
                        case 5001: Add(M, "Defender log", $"{t} real-time protection was turned OFF"); shown++; break;
                        case 5010: Add(M, "Defender log", $"{t} malware scanning was disabled"); shown++; break;
                        case 5012: Add(M, "Defender log", $"{t} virus scanning was disabled"); shown++; break;
                        case 5007:
                            var text = string.Join(" ", e.Properties.Select(p => p.Value?.ToString()));
                            if (text.Contains(@"\Exclusions\", StringComparison.OrdinalIgnoreCase))
                            {
                                Add(M, "Defender log", $"{t} an exclusion was added/changed");
                                shown++;
                            }
                            break;
                    }
                }
            }
        }
        catch
        {
            Out("  (Could not read the Defender event log.)", Tone.Warn);
        }
        Close();
    }

    // ================================================================ 7. threat history
    private static readonly Regex RatNames = new(
        @"backdoor|\brat\b|remcos|asyncrat|njrat|bladabindi|quasar|darkcomet|nanocore|netwire|warzone|ave_?maria|dcrat|venomrat|xworm|agenttesla|redline|lumma|vidar|raccoon|stealer|pws:|keylog|cobaltstrike|meterpreter|metasploit|sliver|bruteratel",
        RegexOptions.IgnoreCase);

    private static readonly Dictionary<int, string> ThreatStatus = new()
    {
        [1] = "Detected", [2] = "Cleaned", [3] = "Quarantined", [4] = "Removed", [5] = "ALLOWED", [6] = "Blocked",
        [102] = "Quarantine FAILED", [103] = "Remove FAILED", [104] = "Allow failed", [105] = "Abandoned", [107] = "Block FAILED"
    };

    private void ThreatHistory()
    {
        Section("7. Defender threat history");
        var names = new Dictionary<long, string>();
        foreach (var t in Wmi.Query(DefenderNs, "SELECT ThreatID, ThreatName FROM MSFT_MpThreat"))
            names[Wmi.Get<long>(t, "ThreatID")] = Wmi.Str(t, "ThreatName");

        var detections = Wmi.Query(DefenderNs, "SELECT * FROM MSFT_MpThreatDetection")
            .Select(o => new
            {
                Id = Wmi.Get<long>(o, "ThreatID"),
                Time = Wmi.Time(o, "InitialDetectionTime"),
                Status = Wmi.Get<int>(o, "ThreatStatusID"),
                Success = Wmi.Get<bool>(o, "ActionSuccess"),
                Resources = Wmi.Arr(o, "Resources")
            })
            .OrderByDescending(d => d.Time)
            .ToList();

        if (detections.Count == 0) Info("No detections recorded (or history was cleared).");

        foreach (var d in detections)
        {
            var name = names.TryGetValue(d.Id, out var n) ? n : $"ThreatID {d.Id}";
            var status = ThreatStatus.TryGetValue(d.Status, out var s) ? s : $"status {d.Status}";
            var res = string.Join("; ", d.Resources.Take(2));
            bool recent = d.Time > since;
            bool bad = new[] { 1, 5, 102, 103, 105, 107 }.Contains(d.Status) || !d.Success;
            bool isRat = RatNames.IsMatch(name);

            string sev;
            if (bad && (recent || isRat)) sev = H;
            else if (isRat && recent) sev = H;        // even if removed, it may have run first
            else if (isRat || bad) sev = M;
            else if (recent) sev = L;
            else sev = I;

            Add(sev, "Threat history", $"{d.Time:yyyy-MM-dd HH:mm}  {name}  [{status}]  {res}");
        }
        Close();
    }

    // ================================================================ 8. local users
    private void LocalUsers()
    {
        Section("8. Local user accounts");
        var mySid = WindowsIdentity.GetCurrent().User?.Value ?? "";

        try
        {
            using var ctx = new PrincipalContext(ContextType.Machine);
            using var searcher = new PrincipalSearcher(new UserPrincipal(ctx));
            foreach (var principal in searcher.FindAll())
            {
                if (principal is not UserPrincipal u) continue;
                var name = u.SamAccountName ?? u.Name ?? "?";
                var sid = u.Sid?.Value ?? "";
                bool enabled = u.Enabled ?? false;
                Info($"{name,-22} Enabled={enabled,-5} LastLogon={u.LastLogon?.ToLocalTime():yyyy-MM-dd HH:mm}  PasswordSet={u.LastPasswordSet?.ToLocalTime():yyyy-MM-dd}");
                if (!enabled) continue;

                if (sid.EndsWith("-501")) Add(H, "Users", $"Guest account '{name}' is ENABLED");
                else if (sid.EndsWith("-500")) Add(M, "Users", $"Built-in Administrator account '{name}' is enabled");
                else if (sid.EndsWith("-503") || sid.EndsWith("-504")) Add(L, "Users", $"System account '{name}' is enabled (normally disabled)");

                if (name.EndsWith("$")) Add(H, "Users", $"Account name ends with '$' (hidden-account trick): {name}");

                if (sid != mySid && u.LastPasswordSet.HasValue && u.LastPasswordSet.Value > DateTime.UtcNow.AddDays(-14))
                    Add(M, "Users", $"Account '{name}' was created or had its password set in the last 14 days");
            }
        }
        catch (Exception ex)
        {
            Out("  (Could not list local users: " + ex.Message + ")", Tone.Warn);
        }

        // Administrators group, found by SID so it works on Thai / any-language Windows
        try
        {
            var group = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\').Last();
            var members = Wmi.Query(@"root\cimv2",
                $"ASSOCIATORS OF {{Win32_Group.Domain='{Environment.MachineName}',Name='{group.Replace("'", "\\'")}'}} WHERE AssocClass=Win32_GroupUser Role=GroupComponent");
            if (members.Count == 0) Out("  (Could not list the Administrators group.)", Tone.Warn);
            foreach (var m in members)
            {
                var full = $"{Wmi.Str(m, "Domain")}\\{Wmi.Str(m, "Name")}";
                var sid = Wmi.Str(m, "SID") ?? "";
                if (sid == mySid || sid.EndsWith("-500")) Info("Administrator: " + full);
                else Add(M, "Users", $"Extra administrator: {full}   <- do you know this account?");
            }
        }
        catch (Exception ex)
        {
            Out("  (Could not list the Administrators group: " + ex.Message + ")", Tone.Warn);
        }
        Close();
    }

    // ================================================================ 9. scheduled tasks
    private void ScheduledTasks()
    {
        Section("9. Scheduled tasks");
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var root = Path.Combine(winDir, "System32", "Tasks");
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 };
        int total = 0, nonMs = 0;

        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(root, "*", opts).ToList(); }
        catch { files = Array.Empty<string>(); }

        foreach (var file in files)
        {
            XDocument doc;
            try { doc = XDocument.Load(file); }
            catch { continue; }

            var label = file.Substring(root.Length);
            bool isMs = label.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
            total++;
            if (!isMs) nonMs++;

            foreach (var exec in doc.Descendants(ns + "Exec"))
            {
                var command = exec.Element(ns + "Command")?.Value?.Trim().Trim('"');
                if (string.IsNullOrEmpty(command)) continue;
                var args = exec.Element(ns + "Arguments")?.Value ?? "";
                var full = $"\"{command}\" {args}".Trim();
                if (!isMs) Info($"{label} -> {full}");
                TestEntry("Scheduled task", label, full, quietMissing: isMs, onlyRiskyPaths: isMs);
            }

            var hidden = doc.Descendants(ns + "Hidden").FirstOrDefault()?.Value;
            if (!isMs && string.Equals(hidden, "true", StringComparison.OrdinalIgnoreCase))
                Add(L, "Scheduled task", $"{label} is marked Hidden");
        }
        Out($"  {total} tasks read, {nonMs} outside \\Microsoft\\.", Tone.Dim);

        // Tasks hidden by deleting their security descriptor (they vanish from Task Scheduler)
        try
        {
            using var tree = Reg.Open(LM, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree");
            if (tree != null) WalkTaskTree(tree, "");
        }
        catch { }
        Close();
    }

    private void WalkTaskTree(RegistryKey key, string path)
    {
        foreach (var sub in key.GetSubKeyNames())
        {
            try
            {
                using var child = key.OpenSubKey(sub);
                if (child == null) continue;
                var values = child.GetValueNames();
                if (values.Contains("Id") && !values.Contains("SD"))
                    Add(H, "Scheduled task", $"Task with its security descriptor removed (invisible in Task Scheduler): {path}\\{sub}");
                WalkTaskTree(child, path + "\\" + sub);
            }
            catch { }
        }
    }

    // ================================================================ 10. network
    private static readonly HashSet<int> RatPorts = new() { 1177, 1604, 2404, 3460, 4444, 4782, 5552, 6606, 7707, 8808, 31337 };

    private void Network()
    {
        Section("10. Network connections");
        var byPid = Procs().GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        var conns = Wmi.Query(@"root\StandardCimv2", "SELECT LocalPort, RemoteAddress, RemotePort, State, OwningProcess FROM MSFT_NetTCPConnection")
            .Select(o => new
            {
                LocalPort = Wmi.Get<int>(o, "LocalPort"),
                Remote = Wmi.Str(o, "RemoteAddress") ?? "",
                RemotePort = Wmi.Get<int>(o, "RemotePort"),
                State = Wmi.Get<int>(o, "State"),   // 2 = Listen, 5 = Established
                Pid = Wmi.Get<uint>(o, "OwningProcess")
            })
            .Where(c => c.State == 2 || (c.State == 5 && !Regex.IsMatch(c.Remote, @"^(127\.|::1$|0\.0\.0\.0$)")))
            .ToList();

        Out($"  {conns.Count} established + listening TCP sockets.");
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in conns)
        {
            byPid.TryGetValue(c.Pid, out var p);
            var pname = p?.Name ?? $"PID {c.Pid}";
            bool listen = c.State == 2;
            var line = listen ? $"{pname} listening on port {c.LocalPort}" : $"{pname} -> {c.Remote}:{c.RemotePort}";
            int port = listen ? c.LocalPort : c.RemotePort;

            if (RatPorts.Contains(port) && reported.Add("port:" + line))
                Add(M, "Network", $"{line}  (port commonly used by RATs)");

            var exe = p?.ExePath;
            if (!string.IsNullOrEmpty(exe) && !reported.Contains(exe) && Paths.Risk(exe) != "None" && !Sig.Get(exe).Valid)
            {
                reported.Add(exe);
                Add(H, "Network", $"Unsigned program in a user-writable folder has network activity: {line}  ({exe})");
            }
        }
        Close();
    }

    // ================================================================ 11. hijacks
    private void Hijacks()
    {
        Section("11. Common hijack / persistence spots");
        const string winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

        var shell = Reg.Str(LM, winlogon, "Shell");
        if (!string.IsNullOrEmpty(shell) && !shell.Trim().TrimEnd(',').Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            Add(H, "Winlogon", $"Shell modified: {shell}  (should be explorer.exe)");

        var userinit = Reg.Str(LM, winlogon, "Userinit");
        if (!string.IsNullOrEmpty(userinit))
        {
            var ui = userinit.Trim().TrimEnd(',');
            if (!ui.Equals(Path.Combine(winDir, "system32", "userinit.exe"), StringComparison.OrdinalIgnoreCase) &&
                !ui.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase))
                Add(H, "Winlogon", $"Userinit modified: {userinit}");
        }

        var userShell = Reg.Str(CU, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell");
        if (!string.IsNullOrEmpty(userShell)) Add(H, "Winlogon", $"Per-user Shell override set: {userShell}");

        foreach (var n in new[] { "Load", "Run" })
        {
            var v = Reg.Str(CU, @"Software\Microsoft\Windows NT\CurrentVersion\Windows", n);
            if (!string.IsNullOrWhiteSpace(v)) Add(H, "Startup (legacy)", $@"HKCU ...\Windows\{n} is set: {v}");
        }

        foreach (var k in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
        {
            var dlls = Reg.Str(LM, k, "AppInit_DLLs");
            if (!string.IsNullOrWhiteSpace(dlls) && Reg.Int(LM, k, "LoadAppInit_DLLs") == 1)
                Add(H, "AppInit", $"AppInit_DLLs loads into every app: {dlls}");
        }

        using (var ifeo = Reg.Open(LM, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"))
        {
            if (ifeo != null)
                foreach (var sub in ifeo.GetSubKeyNames())
                {
                    using var k = ifeo.OpenSubKey(sub);
                    var dbg = k?.GetValue("Debugger")?.ToString();
                    if (!string.IsNullOrWhiteSpace(dbg))
                        Add(M, "IFEO", $"{sub} is redirected to: {dbg}  (fine if you set e.g. Process Explorer)");
                }
        }
        using (var spe = Reg.Open(LM, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"))
        {
            if (spe != null)
                foreach (var sub in spe.GetSubKeyNames())
                {
                    using var k = spe.OpenSubKey(sub);
                    var mon = k?.GetValue("MonitorProcess")?.ToString();
                    if (!string.IsNullOrWhiteSpace(mon)) Add(H, "IFEO", $"When {sub} exits, this runs: {mon}");
                }
        }

        // WMI event subscriptions - fileless persistence
        var consumers = Wmi.Query(@"root\subscription", "SELECT * FROM CommandLineEventConsumer")
            .Concat(Wmi.Query(@"root\subscription", "SELECT * FROM ActiveScriptEventConsumer"));
        foreach (var c in consumers)
        {
            var what = Wmi.Str(c, "CommandLineTemplate");
            if (string.IsNullOrEmpty(what))
            {
                var script = Wmi.Str(c, "ScriptText") ?? "";
                what = script.Length > 120 ? script[..120] : script;
            }
            Add(H, "WMI", $"WMI event consumer '{Wmi.Str(c, "Name")}' runs: {what}");
        }

        // hosts file
        try
        {
            var hosts = Path.Combine(winDir, "System32", "drivers", "etc", "hosts");
            foreach (var raw in File.ReadAllLines(hosts))
            {
                var l = raw.Trim();
                if (l.Length == 0 || l.StartsWith('#')) continue;
                if (Regex.IsMatch(l, "microsoft|windowsupdate|defender|smartscreen|avast|kaspersky|eset|malwarebytes|virustotal|bitdefender|norton|mcafee|sophos|avg", RegexOptions.IgnoreCase))
                    Add(M, "Hosts file", $"Security/update site redirected: {l}");
                else Info("hosts entry: " + l);
            }
        }
        catch { }

        // proxy (used to intercept traffic)
        const string inet = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        if (Reg.Int(CU, inet, "ProxyEnable") == 1)
            Add(M, "Proxy", $"System proxy is enabled: {Reg.Str(CU, inet, "ProxyServer")}");
        var pac = Reg.Str(CU, inet, "AutoConfigURL");
        if (!string.IsNullOrWhiteSpace(pac)) Add(M, "Proxy", $"Proxy auto-config script set: {pac}");
        Close();
    }

    // ================================================================ 12. remote access & firewall
    private void RemoteAccess()
    {
        Section("12. Remote access & firewall");
        if (Reg.Int(LM, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0)
            Add(M, "Remote access", "Remote Desktop (RDP) is ENABLED");
        if (Reg.Int(LM, @"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp") == 1)
            Add(L, "Remote access", "Remote Assistance is allowed");

        foreach (var s in Wmi.Query(@"root\cimv2", "SELECT Name, State FROM Win32_Service WHERE Name='sshd' OR Name='WinRM'"))
        {
            if (Wmi.Str(s, "State") != "Running") continue;
            var n = Wmi.Str(s, "Name");
            Add(L, "Remote access", n.Equals("sshd", StringComparison.OrdinalIgnoreCase)
                ? "OpenSSH Server is running"
                : "WinRM (PowerShell remoting) is running");
        }

        foreach (var fp in Wmi.Query(@"root\StandardCimv2", "SELECT Name, Enabled FROM MSFT_NetFirewallProfile"))
        {
            var name = Wmi.Str(fp, "Name");
            if (Wmi.Get<int>(fp, "Enabled") == 0) Add(H, "Firewall", $"Windows Firewall is OFF for the {name} profile");
            else Out($"  [ON] Firewall - {name} profile", Tone.Ok);
        }

        // Inbound allow rules for programs in user-writable folders (RATs open the firewall for themselves)
        var inbound = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Wmi.Query(@"root\StandardCimv2", "SELECT InstanceID, DisplayName, Enabled, Direction, Action FROM MSFT_NetFirewallRule"))
        {
            // Enabled 1 = True; Direction 1 = Inbound; Action 2 = Allow, 3 = AllowBypass
            if (Wmi.Get<int>(r, "Enabled") != 1 || Wmi.Get<int>(r, "Direction") != 1) continue;
            var action = Wmi.Get<int>(r, "Action");
            if (action != 2 && action != 3) continue;
            var id = Wmi.Str(r, "InstanceID");
            if (id != null) inbound[id] = Wmi.Str(r, "DisplayName");
        }
        foreach (var f in Wmi.Query(@"root\StandardCimv2", "SELECT InstanceID, AppPath FROM MSFT_NetFirewallApplicationFilter"))
        {
            var id = Wmi.Str(f, "InstanceID");
            if (id == null || !inbound.TryGetValue(id, out var display)) continue;
            var prog = Environment.ExpandEnvironmentVariables(Wmi.Str(f, "AppPath") ?? "");
            if (prog.Length == 0 || prog.Equals("Any", StringComparison.OrdinalIgnoreCase) || Paths.Risk(prog) == "None") continue;
            if (!Sig.Get(prog).Valid)
                Add(M, "Firewall", $"Inbound rule '{display}' allows an UNSIGNED program: {prog}");
        }
        Close();
    }

    // ================================================================ 13. dropped files
    private static readonly HashSet<string> DropExts = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".dll", ".vbs", ".js", ".hta", ".bat", ".ps1" };

    private void DroppedFiles()
    {
        Section("13. Recently dropped executables/scripts (last 7 days)");
        var dirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetEnvironmentVariable("PUBLIC"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.Combine(winDir, "Temp")
        }.Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d)).Distinct(StringComparer.OrdinalIgnoreCase);

        var cut = DateTime.Now.AddDays(-7);
        var opts = new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2, IgnoreInaccessible = true, AttributesToSkip = 0 };
        var unsigned = new List<FileInfo>();
        foreach (var d in dirs)
        {
            try
            {
                foreach (var f in new DirectoryInfo(d).EnumerateFiles("*", opts))
                {
                    if (!DropExts.Contains(f.Extension) || f.CreationTime <= cut) continue;
                    if (!Sig.Get(f.FullName).Valid) unsigned.Add(f);
                }
            }
            catch { }
        }

        const int max = 25;
        foreach (var f in unsigned.OrderByDescending(x => x.CreationTime).Take(max))
            Add(L, "New files", $"{f.CreationTime:yyyy-MM-dd HH:mm}  unsigned: {f.FullName}");
        if (unsigned.Count > max) Out($"  ...and {unsigned.Count - max} more.", Tone.Dim);
        Close();
    }

    // ================================================================ summary
    public void Summary()
    {
        Section("SUMMARY");
        var high = Findings.Where(f => f.Severity == H).ToList();
        int med = Findings.Count(f => f.Severity == M);
        int low = Findings.Count(f => f.Severity == L);
        Out($"  HIGH: {high.Count}    MEDIUM: {med}    LOW: {low}", Tone.Bright);
        Out();
        if (high.Count > 0)
        {
            Out("  HIGH items:", Tone.High);
            foreach (var f in high) Out($"   * [{f.Category}] {f.Message}", Tone.High);
            Out();
            Out("  Verdict: SUSPICIOUS - investigate the HIGH items before trusting this PC.", Tone.High);
            Out("  If confirmed: disconnect from the internet, run a Microsoft Defender Offline scan,", Tone.High);
            Out("  and change your passwords FROM ANOTHER DEVICE (Discord, Google, Steam, banking).", Tone.High);
        }
        else if (med > 0)
        {
            Out("  Verdict: PROBABLY OK - review the MEDIUM items (many will be things you set up yourself).", Tone.Medium);
        }
        else
        {
            Out("  Verdict: No common RAT indicators found.", Tone.Ok);
        }
        Out();
        Out("  Note: this is a heuristic scan. A well-made RAT or rootkit can hide from tools running on", Tone.Dim);
        Out("  the same machine. For a second opinion use Sysinternals Autoruns + Process Explorer", Tone.Dim);
        Out("  (with VirusTotal checking on) and a Defender Offline scan.", Tone.Dim);
    }

    public void MiniSummary()
    {
        Out();
        Out($"  Done.  HIGH: {Findings.Count(f => f.Severity == H)}   MEDIUM: {Findings.Count(f => f.Severity == M)}   LOW: {Findings.Count(f => f.Severity == L)}", Tone.Bright);
    }
}
