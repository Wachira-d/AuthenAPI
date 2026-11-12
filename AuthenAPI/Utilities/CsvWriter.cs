using System.Text;

namespace AuthenAPI.Utilities;

/// <summary>
/// Minimal CSV builder with spreadsheet formula-injection protection
/// </summary>
public static class CsvWriter
{
    public static string Build(IEnumerable<string> header, IEnumerable<IEnumerable<object?>> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", header.Select(Escape)));
        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(",", row.Select(v => Escape(Format(v)))));
        }
        return sb.ToString();
    }

    private static string Format(object? value) => value switch
    {
        null => string.Empty,
        DateTime dt => dt.ToString("yyyy-MM-dd HH:mm:ss'Z'"),
        bool b => b ? "true" : "false",
        _ => value.ToString() ?? string.Empty
    };

    private static string Escape(string value)
    {
        // Values coming from clients (usernames, user agents, paths) must not be
        // interpreted as formulas when the CSV is opened in Excel.
        if (value.Length > 0 && "=+-@\t\r".Contains(value[0]))
        {
            value = "'" + value;
        }

        if (value.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0)
        {
            value = "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
