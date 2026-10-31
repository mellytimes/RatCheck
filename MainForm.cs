using System.Diagnostics;
using System.Security.Principal;

namespace RatCheck;

internal sealed class MainForm : Form
{
    private readonly bool isAdmin;
    private readonly RichTextBox report;
    private readonly Pill pillHigh, pillMed, pillLow;
    private readonly Label status;
    private readonly ProgressLine progress;
    private readonly List<RoundButton> buttons = new();
    private readonly List<string> lines = new();
    private readonly Dictionary<string, int> counts = new() { ["HIGH"] = 0, ["MEDIUM"] = 0, ["LOW"] = 0 };
    private bool running;

    private readonly Font fontUi    = new("Segoe UI", 9.75f);
    private readonly Font fontBold  = new("Segoe UI Semibold", 10.5f);
    private readonly Font fontTitle = new("Segoe UI Semibold", 20f);
    private readonly Font fontSmall = new("Segoe UI Semibold", 8.25f);
    private readonly Font fontMono  = new("Consolas", 10f);

    public MainForm()
    {
        isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "RatCheck";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1200, 780);
        MinimumSize = new Size(980, 640);
        BackColor = Theme.Bg;
        ForeColor = Theme.Text;
        Font = fontUi;
        DoubleBuffered = true;
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath); } catch { }

        // ---------------------------------------------------------- report area
        var main = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Padding = new Padding(4, 4, 22, 22) };

        var card = new RoundPanel { Dock = DockStyle.Fill, Padding = new Padding(16, 14, 8, 14) };
        report = new RichTextBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Card,
            ForeColor = Theme.Text,
            BorderStyle = BorderStyle.None,
            Font = fontMono,
            ReadOnly = true,
            WordWrap = false,
            DetectUrls = false,
            HideSelection = false
        };
        report.HandleCreated += (_, _) => NativeUi.DarkScrollbars(report.Handle);
        card.Controls.Add(report);

        var progRow = new Panel { Dock = DockStyle.Top, Height = 16, BackColor = Theme.Bg };
        progress = new ProgressLine { Location = new Point(0, 5), Width = 800, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
        progRow.Controls.Add(progress);
        progRow.Resize += (_, _) => progress.Width = progRow.ClientSize.Width;

        var topRow = new Panel { Dock = DockStyle.Top, Height = 44, BackColor = Theme.Bg };
        pillHigh = new Pill { Text = "HIGH  0",   Accent = Theme.High,   Location = new Point(0, 6),   Size = new Size(104, 30) };
        pillMed  = new Pill { Text = "MEDIUM  0", Accent = Theme.Medium, Location = new Point(114, 6), Size = new Size(120, 30) };
        pillLow  = new Pill { Text = "LOW  0",    Accent = Theme.Low,    Location = new Point(244, 6), Size = new Size(104, 30) };
        status = new Label { Dock = DockStyle.Right, Width = 460, TextAlign = ContentAlignment.MiddleRight, ForeColor = Theme.Dim, Text = "Ready" };
        topRow.Controls.AddRange(new Control[] { pillHigh, pillMed, pillLow, status });

        main.Controls.Add(card);
        main.Controls.Add(progRow);
        main.Controls.Add(topRow);
        card.BringToFront();

        // ---------------------------------------------------------- sidebar
        var side = new Panel { Dock = DockStyle.Left, Width = 278, BackColor = Theme.Bg, AutoScroll = true };

        var full = AddButton(side, "Run Full Scan", 22, 8, 232, 48, centered: true, font: fontBold,
            baseColor: Theme.Accent, hoverColor: Theme.AccentHover);
        full.ForeColor = Theme.Bright;
        full.Click += (_, _) => RunScan(Scanner.Checks, "Full scan", fullScan: true);

        side.Controls.Add(new Label { Text = "INDIVIDUAL CHECKS", Font = fontSmall, ForeColor = Theme.Dim, Location = new Point(26, 70), AutoSize = true });

        int y = 94;
        foreach (var check in Scanner.Checks)
        {
            var c = check;
            var b = AddButton(side, c.Label, 22, y, 232, 32);
            b.Click += (_, _) => RunScan(new[] { c }, c.Label.Trim(), fullScan: false);
            y += 37;
        }

        y += 12;
        side.Controls.Add(new Label { Text = "REPORT", Font = fontSmall, ForeColor = Theme.Dim, Location = new Point(26, y), AutoSize = true });
        y += 24;

        var save = AddButton(side, "Save report", 22, y, 232, 34, centered: true);
        save.Click += (_, _) => SaveReport();
        y += 40;

        var copy = AddButton(side, "Copy", 22, y, 112, 34, centered: true);
        copy.Click += (_, _) =>
        {
            if (lines.Count == 0) return;
            Clipboard.SetText(string.Join(Environment.NewLine, lines));
            status.Text = "Report copied to clipboard";
        };
        var clear = AddButton(side, "Clear", 142, y, 112, 34, centered: true);
        clear.Click += (_, _) => { ResetReport(); status.Text = "Ready"; };

        // ---------------------------------------------------------- header
        var header = new Panel { Dock = DockStyle.Top, Height = 84, Width = ClientSize.Width, BackColor = Theme.Bg };
        header.Controls.Add(new Label { Text = "RatCheck", Font = fontTitle, ForeColor = Theme.Bright, Location = new Point(20, 12), AutoSize = true });
        header.Controls.Add(new Label
        {
            Text = "Windows RAT / persistence scanner  -  read-only, changes nothing",
            ForeColor = Theme.Dim, Location = new Point(24, 52), AutoSize = true
        });
        var badge = new Pill
        {
            Text = isAdmin ? "ADMINISTRATOR" : "NOT ADMIN",
            Accent = isAdmin ? Theme.Ok : Theme.Low,
            Size = new Size(140, 32),
            Location = new Point(header.Width - 24 - 140, 26),
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        header.Controls.Add(badge);

        Controls.Add(main);
        Controls.Add(side);
        Controls.Add(header);
        main.BringToFront();

        ResumeLayout(false);
        PerformLayout();

        Shown += (_, _) => ShowWelcome();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        NativeUi.DarkTitleBar(Handle);
    }

    private RoundButton AddButton(Control parent, string text, int x, int y, int w, int h,
        bool centered = false, Font font = null, Color? baseColor = null, Color? hoverColor = null)
    {
        var b = new RoundButton
        {
            Text = text,
            Location = new Point(x, y),
            Size = new Size(w, h),
            Centered = centered,
            Font = font ?? fontUi,
            BaseColor = baseColor ?? Theme.Btn,
            HoverColor = hoverColor ?? Theme.BtnHover
        };
        parent.Controls.Add(b);
        buttons.Add(b);
        return b;
    }

    // ---------------------------------------------------------- report helpers
    private void Append(string text, Tone tone, bool keep = true)
    {
        report.SelectionStart = report.TextLength;
        report.SelectionLength = 0;
        report.SelectionColor = Theme.For(tone);
        report.AppendText(text + Environment.NewLine);
        report.SelectionColor = Theme.Text;
        report.ScrollToCaret();
        if (keep) lines.Add(text);
    }

    private void UpdatePills()
    {
        pillHigh.Text = $"HIGH  {counts["HIGH"]}";
        pillMed.Text  = $"MEDIUM  {counts["MEDIUM"]}";
        pillLow.Text  = $"LOW  {counts["LOW"]}";
    }

    private void ResetReport()
    {
        report.Clear();
        lines.Clear();
        foreach (var k in counts.Keys.ToList()) counts[k] = 0;
        UpdatePills();
        progress.Value = 0;
    }

    private void ShowWelcome()
    {
        Append("  Welcome to RatCheck.", Tone.Bright, keep: false);
        Append("", Tone.Text, keep: false);
        Append("  > Run Full Scan       runs all 13 checks and gives a verdict.", Tone.Text, keep: false);
        Append("  > Individual checks   run one check on its own.", Tone.Text, keep: false);
        Append("  > Save / Copy         export whatever is in this report.", Tone.Text, keep: false);
        Append("", Tone.Text, keep: false);
        Append("  Colours:  [HIGH] investigate   [MEDIUM] review   [LOW] usually harmless   [OK] clean", Tone.Dim, keep: false);
        if (!isAdmin)
        {
            Append("", Tone.Text, keep: false);
            Append("  Not running as Administrator - some checks will be incomplete.", Tone.Warn, keep: false);
        }
    }

    private void SaveReport()
    {
        if (lines.Count == 0) return;
        using var dlg = new SaveFileDialog
        {
            Filter = "Text file (*.txt)|*.txt",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            FileName = $"RatCheck_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllLines(dlg.FileName, lines);
        status.Text = "Saved to " + dlg.FileName;
    }

    private void SetBusy(bool busy)
    {
        foreach (var b in buttons) b.Enabled = !busy;
        Cursor = busy ? Cursors.AppStarting : Cursors.Default;
    }

    // ---------------------------------------------------------- run checks on a background thread
    private async void RunScan(IReadOnlyList<(string Label, Action<Scanner> Run)> steps, string title, bool fullScan)
    {
        if (running) return;
        running = true;
        SetBusy(true);
        ResetReport();
        var sw = Stopwatch.StartNew();

        var scanner = new Scanner(isAdmin);
        scanner.Line += (text, tone) => BeginInvoke((Action)(() => Append(text, tone)));
        scanner.Status += s => BeginInvoke((Action)(() => status.Text = "Running: " + s));
        scanner.Found += f => BeginInvoke((Action)(() =>
        {
            if (counts.ContainsKey(f.Severity)) counts[f.Severity]++;
            UpdatePills();
        }));

        try
        {
            await Task.Run(() =>
            {
                scanner.Header(title);
                for (int i = 0; i < steps.Count; i++)
                {
                    float frac = (float)i / steps.Count;
                    BeginInvoke((Action)(() => progress.Value = frac));
                    try { steps[i].Run(scanner); }
                    catch (Exception ex) { scanner.Out("  [error] " + ex.Message, Tone.Dim); }
                }
                if (fullScan) scanner.Summary();
                else scanner.MiniSummary();
            });
        }
        finally
        {
            sw.Stop();
            // let queued report lines land before re-enabling the buttons
            BeginInvoke((Action)(() =>
            {
                progress.Value = 1;
                status.Text = $"Finished in {sw.Elapsed.TotalSeconds:N1}s";
                SetBusy(false);
                running = false;
            }));
        }
    }
}
