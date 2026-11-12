using System.Net;
using System.Net.Sockets;

namespace AuthenAPI.Utilities;

/// <summary>
/// Matches IP addresses against a list of IPs / CIDR ranges
/// </summary>
public sealed class IpNetworkMatcher
{
    private readonly List<(IPAddress Network, int PrefixLength)> _networks;

    public int Count => _networks.Count;

    private IpNetworkMatcher(List<(IPAddress, int)> networks) => _networks = networks;

    public static IpNetworkMatcher Parse(IEnumerable<string>? entries)
    {
        var list = new List<(IPAddress, int)>();
        foreach (var entry in entries ?? Enumerable.Empty<string>())
        {
            if (TryParseEntry(entry, out var network, out var prefix))
            {
                list.Add((network, prefix));
            }
        }
        return new IpNetworkMatcher(list);
    }

    /// <summary>
    /// Validate an IP or CIDR entry such as "10.0.0.0/8" or "192.168.1.10"
    /// </summary>
    public static bool TryParseEntry(string? entry, out IPAddress network, out int prefixLength)
    {
        network = IPAddress.None;
        prefixLength = 0;
        if (string.IsNullOrWhiteSpace(entry)) return false;

        var text = entry.Trim();
        var slash = text.IndexOf('/');
        var ipPart = slash >= 0 ? text[..slash] : text;

        if (!IPAddress.TryParse(ipPart, out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        var maxPrefix = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maxPrefix;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..], out prefix) || prefix < 0 || prefix > maxPrefix))
        {
            return false;
        }

        network = ip;
        prefixLength = prefix;
        return true;
    }

    public bool Contains(IPAddress? address)
    {
        if (address == null) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        foreach (var (network, prefixLength) in _networks)
        {
            if (IsInNetwork(address, network, prefixLength)) return true;
        }
        return false;
    }

    private static bool IsInNetwork(IPAddress address, IPAddress network, int prefixLength)
    {
        if (address.AddressFamily != network.AddressFamily) return false;

        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var i = 0; i < fullBytes; i++)
        {
            if (addressBytes[i] != networkBytes[i]) return false;
        }

        if (remainingBits > 0 && fullBytes < addressBytes.Length)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            if ((addressBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) return false;
        }

        return true;
    }
}
