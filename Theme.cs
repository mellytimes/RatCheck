using System.Drawing.Drawing2D;

namespace RatCheck;

internal static class Theme
{
    public static readonly Color Bg          = ColorTranslator.FromHtml("#0A0A0D");
    public static readonly Color Card        = ColorTranslator.FromHtml("#121218");
    public static readonly Color Border      = ColorTranslator.FromHtml("#23232D");
    public static readonly Color Btn         = ColorTranslator.FromHtml("#1B1B23");
    public static readonly Color BtnHover    = ColorTranslator.FromHtml("#282834");
    public static readonly Color BtnDisabled = ColorTranslator.FromHtml("#141419");
    public static readonly Color Accent      = ColorTranslator.FromHtml("#7C5CFF");
    public static readonly Color AccentHover = ColorTranslator.FromHtml("#957BFF");
    public static readonly Color Text        = ColorTranslator.FromHtml("#E4E4EC");
    public static readonly Color Bright      = Color.White;
    public static readonly Color Dim         = ColorTranslator.FromHtml("#7A7A8A");
    public static readonly Color Section     = ColorTranslator.FromHtml("#5CC8FF");
    public static readonly Color High        = ColorTranslator.FromHtml("#FF5C6C");
    public static readonly Color Medium      = ColorTranslator.FromHtml("#FFC14D");
    public static readonly Color Low         = ColorTranslator.FromHtml("#E89B4C");
    public static readonly Color Ok          = ColorTranslator.FromHtml("#4ADE80");

    public static Color For(Tone tone) => tone switch
    {
        Tone.Dim => Dim,
        Tone.Bright => Bright,
        Tone.Section => Section,
        Tone.High => High,
        Tone.Medium => Medium,
        Tone.Low => Low,
        Tone.Ok => Ok,
        Tone.Warn => Low,
        Tone.Border => Border,
        _ => Text
    };

    public static GraphicsPath Round(RectangleF r, float radius)
    {
        float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
        var p = new GraphicsPath();
        if (d <= 0) { p.AddRectangle(r); return p; }
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }
}

/// <summary>Pill-shaped button drawn by hand so it can have rounded corners.</summary>
internal sealed class RoundButton : Button
{
    private bool hover;

    public Color BaseColor { get; set; } = Theme.Btn;
    public Color HoverColor { get; set; } = Theme.BtnHover;
    public bool Centered { get; set; }
    public float Radius { get; set; } = 14f;

    public RoundButton()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        Cursor = Cursors.Hand;
        ForeColor = Theme.Text;
        BackColor = Theme.Bg;
        TabStop = false;
    }

    protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? Theme.Bg);

        var fill = !Enabled ? Theme.BtnDisabled : hover ? HoverColor : BaseColor;
        using (var path = Theme.Round(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), Math.Min(Radius, Height / 2f)))
        using (var brush = new SolidBrush(fill))
            g.FillPath(brush, path);

        var fore = Enabled ? ForeColor : Theme.Dim;
        var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine |
                    (Centered ? TextFormatFlags.HorizontalCenter : TextFormatFlags.Left);
        var rect = Centered ? ClientRectangle : new Rectangle(16, 0, Width - 24, Height);
        TextRenderer.DrawText(g, Text, Font, rect, fore, flags);
    }
}

/// <summary>Small rounded badge, used for the HIGH / MEDIUM / LOW counters.</summary>
internal sealed class Pill : Control
{
    public Color Accent { get; set; } = Theme.Text;

    public Pill()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Font = new Font("Segoe UI Semibold", 8.25f);
    }

    protected override void OnTextChanged(EventArgs e) { Invalidate(); base.OnTextChanged(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        using (var path = Theme.Round(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), Height / 2f))
        using (var bg = new SolidBrush(Color.FromArgb(38, Accent)))
        using (var pen = new Pen(Color.FromArgb(110, Accent), 1f))
        {
            g.FillPath(bg, path);
            g.DrawPath(pen, path);
        }
        TextRenderer.DrawText(g, Text, Font, ClientRectangle, Accent,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
    }
}

/// <summary>Panel with a rounded, bordered background (holds the report).</summary>
internal sealed class RoundPanel : Panel
{
    public RoundPanel()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Bg;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        using var path = Theme.Round(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), 16f);
        using var brush = new SolidBrush(Theme.Card);
        using var pen = new Pen(Theme.Border, 1f);
        g.FillPath(brush, path);
        g.DrawPath(pen, path);
    }
}

/// <summary>Thin rounded progress line.</summary>
internal sealed class ProgressLine : Control
{
    private float value;

    public float Value
    {
        get => value;
        set { this.value = Math.Clamp(value, 0f, 1f); Invalidate(); }
    }

    public ProgressLine()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Height = 6;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        using (var track = Theme.Round(new RectangleF(0, 0, Width - 1, Height - 1), Height / 2f))
        using (var b = new SolidBrush(Theme.Border))
            g.FillPath(b, track);
        float w = (Width - 1) * value;
        if (w >= Height)
        {
            using var fill = Theme.Round(new RectangleF(0, 0, w, Height - 1), Height / 2f);
            using var b = new SolidBrush(Theme.Accent);
            g.FillPath(b, fill);
        }
    }
}
