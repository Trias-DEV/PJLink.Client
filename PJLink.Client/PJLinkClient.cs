using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace PJLink.Client;

/// <summary>
/// A client implementation of the PJLink protocol for projector control.
/// This client only supports PJLink Class 1 devices and commands.
/// Class 1 features include:
/// <list type="bullet">
/// <item><description>Power control</description></item>
/// <item><description>Input source selection</description></item>
/// <item><description>Audio/Video mute control</description></item>
/// <item><description>Error status</description></item>
/// <item><description>Lamp status</description></item>
/// <item><description>Input source information</description></item>
/// <item><description>Projector/Display name</description></item>
/// <item><description>Manufacturer name</description></item>
/// <item><description>Product name/model</description></item>
/// <item><description>Other information</description></item>
/// </list>
/// </summary>
public class PJLinkClient : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _password;
    private string? _authHash;
    private const int DefaultPort = 4352;
    private const int RandomNumberTimeout = 30000; // 30 seconds in milliseconds
    private const int ErrorResponseDelay = 2000; // 2 seconds in milliseconds

    /// <summary>
    /// Represents the power status of the projector.
    /// </summary>
    public enum PowerStatus
    {
        /// <summary>
        /// The power status is unknown or could not be determined.
        /// </summary>
        Unknown = -1,

        /// <summary>
        /// The projector is in standby mode.
        /// </summary>
        StandBy = 0,

        /// <summary>
        /// The projector is powered on and operating.
        /// </summary>
        PoweredOn = 1,

        /// <summary>
        /// The projector is in cooling mode.
        /// </summary>
        Cooling = 2,

        /// <summary>
        /// The projector is warming up.
        /// </summary>
        WarmUp = 3
    }

    /// <summary>
    /// Contains information about various error states of the projector.
    /// </summary>
    public class ErrorStatusInfo
    {
        /// <summary>
        /// Gets or sets the fan error status.
        /// </summary>
        public int Fan { get; set; }

        /// <summary>
        /// Gets or sets the lamp error status.
        /// </summary>
        public int Lamp { get; set; }

        /// <summary>
        /// Gets or sets the temperature error status.
        /// </summary>
        public int Temperature { get; set; }

        /// <summary>
        /// Gets or sets the cover open error status.
        /// </summary>
        public int CoverOpen { get; set; }

        /// <summary>
        /// Gets or sets the filter error status.
        /// </summary>
        public int Filter { get; set; }

        /// <summary>
        /// Gets or sets other error statuses.
        /// </summary>
        public int Other { get; set; }

        /// <summary>
        /// Returns a string representation of all error states.
        /// </summary>
        public override string ToString()
        {
            return $"Fan: {GetStatusText(Fan)}, " +
                   $"Lamp: {GetStatusText(Lamp)}, " +
                   $"Temperature: {GetStatusText(Temperature)}, " +
                   $"Cover: {GetStatusText(CoverOpen)}, " +
                   $"Filter: {GetStatusText(Filter)}, " +
                   $"Other: {GetStatusText(Other)}";
        }

        private static string GetStatusText(int status) => status switch
        {
            0 => "OK",
            1 => "Warning",
            2 => "Error",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Contains information about the projector's lamp.
    /// </summary>
    public class LampInfo
    {
        /// <summary>
        /// Gets or sets the number of hours the lamp has been in use.
        /// </summary>
        public int Hours { get; set; }

        /// <summary>
        /// Gets or sets whether the lamp is currently on.
        /// </summary>
        public bool IsOn { get; set; }

        /// <summary>
        /// Returns a string representation of the lamp information.
        /// </summary>
        public override string ToString() => $"Hours: {Hours}, State: {(IsOn ? "On" : "Off")}";
    }

    /// <summary>
    /// Initializes a new instance of the PJLinkClient class.
    /// </summary>
    /// <param name="host">The IP address or hostname of the projector.</param>
    /// <param name="password">The password for authentication (max 32 characters).</param>
    /// <param name="port">The port number (default: 4352).</param>
    /// <exception cref="ArgumentNullException">Thrown when host is null or empty.</exception>
    /// <exception cref="ArgumentException">Thrown when password is longer than 32 characters.</exception>
    public PJLinkClient(string host, string password, int port = DefaultPort)
    {
        if (string.IsNullOrEmpty(host))
            throw new ArgumentNullException(nameof(host));
        
        if (password?.Length > 32)
            throw new ArgumentException("Password must be 32 or fewer ASCII alphanumeric characters", nameof(password));

        _host = host;
        _port = port;
        _password = password ?? string.Empty;
    }

    private async Task<(TcpClient client, NetworkStream stream, bool requiresAuth)> ConnectAsync(CancellationToken cancellationToken)
    {
        var client = new TcpClient();
        await client.ConnectAsync(_host, _port, cancellationToken);
        var stream = client.GetStream();

        var initialResponse = await ReceiveResponseAsync(stream, cancellationToken);
        
        if (initialResponse.StartsWith("PJLINK 0", StringComparison.OrdinalIgnoreCase))
            return (client, stream, false);
        
        if (!initialResponse.StartsWith("PJLINK 1", StringComparison.OrdinalIgnoreCase))
        {
            client.Dispose();
            throw new InvalidOperationException($"Invalid initial response format: {initialResponse}");
        }

        var randomNumber = initialResponse[9..^1];
        _authHash = CalculateMd5Hash(randomNumber + _password);
        
        return (client, stream, true);
    }

    private static string CalculateMd5Hash(string input)
    {
        using var md5 = MD5.Create();
        var inputBytes = Encoding.ASCII.GetBytes(input);
        var hashBytes = md5.ComputeHash(inputBytes);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    /// <summary>
    /// Authenticates with the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>True if authentication was successful, false otherwise.</returns>
    public async Task<bool> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var (client, stream, requiresAuth) = await ConnectAsync(cancellationToken);
            
            if (!requiresAuth)
            {
                client.Dispose();
                return true;
            }

            var command = $"{_authHash}{PJLinkCommands.CommandPrefix}{PJLinkCommands.Power.Command} {PJLinkCommands.Power.QueryParameter}\r";
            await SendCommandAsync(stream, command, cancellationToken);

            var response = await ReceiveResponseAsync(stream, cancellationToken);
            client.Dispose();
            
            return !response.Contains(PJLinkCommands.ErrorResponses.AuthenticationError);
        }
        catch
        {
            throw;
        }
    }

    private async Task<string> ExecuteCommandAsync(string command, CancellationToken cancellationToken)
    {
        var (client, stream, requiresAuth) = await ConnectAsync(cancellationToken);
        try
        {
            var fullCommand = requiresAuth ? $"{_authHash}{command}" : command;
            await SendCommandAsync(stream, fullCommand, cancellationToken);
            return await ReceiveResponseAsync(stream, cancellationToken);
        }
        finally
        {
            client.Dispose();
        }
    }

    private static async Task SendCommandAsync(NetworkStream stream, string command, CancellationToken cancellationToken)
    {
        var bytes = Encoding.ASCII.GetBytes(command + "\r");
        await stream.WriteAsync(bytes, cancellationToken);
    }

    private static async Task<string> ReceiveResponseAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        var received = await stream.ReadAsync(buffer, cancellationToken);
        return Encoding.ASCII.GetString(buffer, 0, received);
    }

    /// <summary>
    /// Powers on the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current power status after the command is executed.</returns>
    public async Task<PowerStatus> PowerOnAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.Power.Command} {PJLinkCommands.Power.PowerOn}", 
            cancellationToken);
        return ParsePowerStatus(response);
    }

    /// <summary>
    /// Powers off the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current power status after the command is executed.</returns>
    public async Task<PowerStatus> PowerOffAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.Power.Command} {PJLinkCommands.Power.PowerOff}", 
            cancellationToken);
        return ParsePowerStatus(response);
    }

    /// <summary>
    /// Gets the current power status of the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current power status.</returns>
    public async Task<PowerStatus> GetPowerStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.Power.Command} {PJLinkCommands.Power.QueryParameter}", 
            cancellationToken);
        return ParsePowerStatus(response);
    }

    /// <summary>
    /// Gets the current input source of the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current input source.</returns>
    public async Task<PJLinkCommands.Input.Source> GetCurrentInputAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.Input.Command} {PJLinkCommands.Input.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting input: {response}");

        var value = response.Split('=').LastOrDefault()?.Trim();
        if (value == null || !int.TryParse(value, out var inputValue))
            throw new InvalidOperationException("Invalid input response format");

        return (PJLinkCommands.Input.Source)inputValue;
    }

    /// <summary>
    /// Sets the input source of the projector.
    /// </summary>
    /// <param name="source">The input source to set.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current input source after the command is executed.</returns>
    public async Task<PJLinkCommands.Input.Source> SetInputAsync(PJLinkCommands.Input.Source source, CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.Input.Command} {(int)source}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error setting input: {response}");

        return await GetCurrentInputAsync(cancellationToken);
    }

    /// <summary>
    /// Gets the current mute status of the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current mute state.</returns>
    public async Task<PJLinkCommands.AudioVideoMute.MuteState> GetMuteStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.AudioVideoMute.Command} {PJLinkCommands.AudioVideoMute.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting mute status: {response}");

        var value = response.Split('=').LastOrDefault()?.Trim();
        if (value == null || !int.TryParse(value, out var muteValue))
            throw new InvalidOperationException("Invalid mute status response format");

        return (PJLinkCommands.AudioVideoMute.MuteState)muteValue;
    }

    /// <summary>
    /// Sets the mute state of the projector.
    /// </summary>
    /// <param name="state">The mute state to set.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current mute state after the command is executed.</returns>
    public async Task<PJLinkCommands.AudioVideoMute.MuteState> SetMuteAsync(PJLinkCommands.AudioVideoMute.MuteState state, CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.AudioVideoMute.Command} {(int)state}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error setting mute: {response}");

        return await GetMuteStatusAsync(cancellationToken);
    }

    /// <summary>
    /// Gets the error status information from the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current error status information.</returns>
    public async Task<ErrorStatusInfo> GetErrorStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.ErrorStatus.Command} {PJLinkCommands.ErrorStatus.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting error status: {response}");

        var value = response.Split('=').LastOrDefault()?.Trim();
        if (value == null || value.Length != 6)
            throw new InvalidOperationException("Invalid error status response format");

        return new ErrorStatusInfo
        {
            Fan = int.Parse(value[0].ToString()),
            Lamp = int.Parse(value[1].ToString()),
            Temperature = int.Parse(value[2].ToString()),
            CoverOpen = int.Parse(value[3].ToString()),
            Filter = int.Parse(value[4].ToString()),
            Other = int.Parse(value[5].ToString())
        };
    }

    /// <summary>
    /// Gets information about the projector's lamp.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current lamp information.</returns>
    public async Task<LampInfo> GetLampInfoAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.LampStatus.Command} {PJLinkCommands.LampStatus.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting lamp info: {response}");

        var value = response.Split('=').LastOrDefault()?.Trim();
        if (value == null)
            throw new InvalidOperationException("Invalid lamp info response format");

        var parts = value.Split(' ');
        if (parts.Length != 2)
            throw new InvalidOperationException("Invalid lamp info response format");

        return new LampInfo
        {
            Hours = int.Parse(parts[0]),
            IsOn = parts[1] == "1"
        };
    }

    /// <summary>
    /// Gets the name of the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The projector name.</returns>
    public async Task<string> GetProjectorNameAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.ProjectorName.Command} {PJLinkCommands.ProjectorName.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting projector name: {response}");

        return response.Split('=').LastOrDefault()?.Trim() ?? string.Empty;
    }

    /// <summary>
    /// Gets the manufacturer name of the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The manufacturer name.</returns>
    public async Task<string> GetManufacturerNameAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.ManufacturerName.Command} {PJLinkCommands.ManufacturerName.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting manufacturer name: {response}");

        return response.Split('=').LastOrDefault()?.Trim() ?? string.Empty;
    }

    /// <summary>
    /// Gets the product name of the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The product name.</returns>
    public async Task<string> GetProductNameAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.ProductName.Command} {PJLinkCommands.ProductName.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting product name: {response}");

        return response.Split('=').LastOrDefault()?.Trim() ?? string.Empty;
    }

    /// <summary>
    /// Gets other information about the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>Other projector information.</returns>
    public async Task<string> GetOtherInfoAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExecuteCommandAsync(
            $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.OtherInfo.Command} {PJLinkCommands.OtherInfo.QueryParameter}", 
            cancellationToken);

        if (response.Contains("ERR"))
            throw new InvalidOperationException($"Error getting other info: {response}");

        return response.Split('=').LastOrDefault()?.Trim() ?? string.Empty;
    }

    /// <summary>
    /// Gets a list of available input sources supported by the projector.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A list of available input sources. If the device doesn't support input listing, returns null.</returns>
    public async Task<IReadOnlyList<PJLinkCommands.Input.Source>?> GetAvailableInputsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await ExecuteCommandAsync(
                $"{PJLinkCommands.CommandPrefix}{PJLinkCommands.InputList.Command} {PJLinkCommands.InputList.QueryParameter}", 
                cancellationToken);

            if (response.Contains("ERR"))
            {
                // Device might not support INST command
                return null;
            }

            var value = response.Split('=').LastOrDefault()?.Trim();
            if (string.IsNullOrEmpty(value))
                return Array.Empty<PJLinkCommands.Input.Source>();

            return value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(s => int.TryParse(s, out var _))
                .Select(s => (PJLinkCommands.Input.Source)int.Parse(s))
                .ToArray();
        }
        catch
        {
            // If there's any error, return null to indicate the feature isn't supported
            return null;
        }
    }

    /// <summary>
    /// Gets a human-readable description of an input source, including its physical connection type.
    /// </summary>
    /// <param name="source">The input source.</param>
    /// <returns>A string describing the input source and its physical connection.</returns>
    public static string GetInputDescription(PJLinkCommands.Input.Source source)
    {
        var name = source.ToString().Replace('_', ' ');
        var type = source switch
        {
            PJLinkCommands.Input.Source.RGB_DSub => "(D-SUB Connector)",
            PJLinkCommands.Input.Source.RGB_BNC => "(5 BNC Connectors)",
            PJLinkCommands.Input.Source.RGB_DviAnalog => "(DVI-I Analog)",
            PJLinkCommands.Input.Source.RGB_Scart => "(SCART RGB)",
            PJLinkCommands.Input.Source.RGB_M1DA => "(M1-DA Analog)",
            PJLinkCommands.Input.Source.Video_Composite => "(RCA Composite)",
            PJLinkCommands.Input.Source.Video_Component => "(3 RCA Component)",
            PJLinkCommands.Input.Source.Video_ComponentBNC => "(3 BNC Component)",
            PJLinkCommands.Input.Source.Video_SVideo => "(Mini-DIN 4-pin)",
            PJLinkCommands.Input.Source.Video_DTerminal => "(D-Terminal)",
            PJLinkCommands.Input.Source.Digital_DviDigital => "(DVI-I Digital)",
            PJLinkCommands.Input.Source.Digital_DviD => "(DVI-D)",
            PJLinkCommands.Input.Source.Digital_Hdmi => "(HDMI)",
            PJLinkCommands.Input.Source.Digital_Sdi => "(SDI)",
            PJLinkCommands.Input.Source.Digital_DisplayPort => "(DisplayPort)",
            PJLinkCommands.Input.Source.Digital_WirelessHdmi => "(Wireless HDMI)",
            PJLinkCommands.Input.Source.Storage_Usb => "(USB Type A)",
            PJLinkCommands.Input.Source.Storage_PcCard => "(PC Card)",
            PJLinkCommands.Input.Source.Storage_CompactFlash => "(CF Card)",
            PJLinkCommands.Input.Source.Storage_SdCard => "(SD Card)",
            PJLinkCommands.Input.Source.Network_Wired => "(RJ-45)",
            PJLinkCommands.Input.Source.Network_Wireless => "(Wi-Fi)",
            PJLinkCommands.Input.Source.Network_UsbB => "(USB Type B)",
            PJLinkCommands.Input.Source.Network_WirelessUsb => "(Wireless USB)",
            PJLinkCommands.Input.Source.Network_Bluetooth => "(Bluetooth)",
            _ => ""
        };

        return string.IsNullOrEmpty(type) ? name : $"{name} {type}";
    }

    private static PowerStatus ParsePowerStatus(string response)
    {
        if (response.Contains("ERR"))
            return PowerStatus.Unknown;

        var status = response.Split('=').LastOrDefault()?.Trim();
        if (status == null || !int.TryParse(status, out var powerStatus))
            return PowerStatus.Unknown;

        return powerStatus switch
        {
            0 => PowerStatus.StandBy,
            1 => PowerStatus.PoweredOn,
            2 => PowerStatus.Cooling,
            3 => PowerStatus.WarmUp,
            _ => PowerStatus.Unknown
        };
    }

    /// <summary>
    /// Releases any resources used by the client.
    /// </summary>
    public void Dispose()
    {
        // Nothing to dispose anymore as connections are handled per-command
        GC.SuppressFinalize(this);
    }
} 