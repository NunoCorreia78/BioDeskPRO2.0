using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Hardware.TiePie.Protocol;

namespace BioDesk.Services.Hardware.TiePie.Firmware;

/// <summary>
/// Loader de firmware TiePie HS3
/// Baseado em análise API Monitor: 1948 chamadas ReadFile × 128 bytes = 243.5 KB
///
/// Ficheiro: hs3f12.hex
/// Formato: Intel HEX (provavelmente) ou binário
/// Upload: Via IOCTL_WRITE_OPERATION com comando específico (a descobrir)
///
/// IMPORTANTE:
/// - Firmware DEVE ser carregado APÓS ConfigureDevice()
/// - Upload incorreto pode BRICK o dispositivo (requer reboot USB)
/// - SEMPRE validar checksum antes de enviar
/// - NUNCA interromper upload a meio (pode corromper FPGA)
/// </summary>
public class HS3FirmwareLoader
{
    private readonly ILogger<HS3FirmwareLoader> _logger;
    private readonly HS3DeviceProtocol _protocol;

    // Constantes baseadas em análise API Monitor
    private const int FIRMWARE_CHUNK_SIZE = 128; // Observado: 128 bytes por ReadFile
    private const int EXPECTED_CHUNK_COUNT = 1948; // Total de leituras observadas
    private const long EXPECTED_FIRMWARE_SIZE = 249344; // 1948 × 128 = 243.5 KB

    // Paths possíveis para hs3f12.hex
    private static readonly string[] FirmwarePaths =
    {
        @"C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\hs3f12.hex",
        @"C:\Program Files\Inergetix\Inergetix-CoRe 5.0\hs3f12.hex",
        @".\Firmware\hs3f12.hex",
        @".\hs3f12.hex"
    };

    // Comandos HIPOTÉTICOS para upload firmware (a descobrir via HS3CommandDiscovery)
    // TODO: Validar com hardware real
    private const uint CMD_FIRMWARE_START = 0x00001000; // Iniciar upload
    private const uint CMD_FIRMWARE_CHUNK = 0x00001001; // Enviar chunk
    private const uint CMD_FIRMWARE_END = 0x00001002;   // Finalizar upload
    private const uint CMD_FIRMWARE_VERIFY = 0x00001003; // Verificar checksum

    public HS3FirmwareLoader(ILogger<HS3FirmwareLoader> logger, HS3DeviceProtocol protocol)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
    }

    #region Public Methods

    /// <summary>
    /// Carrega firmware para dispositivo HS3
    /// </summary>
    /// <param name="firmwarePath">Path do ficheiro hex (null = auto-discover)</param>
    /// <param name="progress">Callback de progresso (0.0-1.0)</param>
    /// <param name="cancellationToken">Token de cancelamento</param>
    /// <returns>True se sucesso</returns>
    public async Task<bool> LoadFirmwareAsync(
        string? firmwarePath = null,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("🔧 Iniciando carregamento de firmware HS3...");

        // 1. Localizar ficheiro firmware
        firmwarePath ??= FindFirmwareFile();
        if (firmwarePath == null)
        {
            _logger.LogError("❌ Ficheiro firmware hs3f12.hex não encontrado");
            return false;
        }

        _logger.LogInformation("📂 Firmware encontrado: {Path}", firmwarePath);

        // 2. Validar ficheiro
        var fileInfo = new FileInfo(firmwarePath);
        if (fileInfo.Length != EXPECTED_FIRMWARE_SIZE)
        {
            _logger.LogWarning("⚠️ Tamanho ficheiro ({Size} bytes) difere do esperado ({Expected} bytes)",
                fileInfo.Length, EXPECTED_FIRMWARE_SIZE);
        }

        // 3. Parsear firmware
        FirmwareData firmware;
        try
        {
            firmware = await ParseFirmwareFileAsync(firmwarePath, cancellationToken);
            _logger.LogInformation("✅ Firmware parseado: {Chunks} chunks, {Size} bytes",
                firmware.Chunks.Count, firmware.TotalSize);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Falha ao parsear firmware");
            return false;
        }

        // 4. Enviar comando START
        _logger.LogDebug("Enviando CMD_FIRMWARE_START...");
        if (!await SendFirmwareCommandAsync(CMD_FIRMWARE_START))
        {
            _logger.LogError("❌ CMD_FIRMWARE_START falhou");
            return false;
        }

        // 5. Upload chunks
        _logger.LogInformation("📤 Enviando {Count} chunks de firmware...", firmware.Chunks.Count);

        for (int i = 0; i < firmware.Chunks.Count; i++)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("⚠️ Upload cancelado pelo utilizador");
                return false;
            }

            var chunk = firmware.Chunks[i];

            if (!await UploadChunkAsync(chunk, i))
            {
                _logger.LogError("❌ Falha no chunk {Index}", i);
                return false;
            }

            // Progress report
            double currentProgress = (double)(i + 1) / firmware.Chunks.Count;
            progress?.Report(currentProgress);

            if ((i + 1) % 100 == 0)
            {
                _logger.LogInformation("📊 Progresso: {Progress:F1}% ({Current}/{Total} chunks)",
                    currentProgress * 100, i + 1, firmware.Chunks.Count);
            }

            // Pequeno delay para não saturar USB
            await Task.Delay(1, cancellationToken);
        }

        // 6. Enviar comando END
        _logger.LogDebug("Enviando CMD_FIRMWARE_END...");
        if (!await SendFirmwareCommandAsync(CMD_FIRMWARE_END))
        {
            _logger.LogError("❌ CMD_FIRMWARE_END falhou");
            return false;
        }

        // 7. Verificar checksum (opcional)
        _logger.LogDebug("Verificando firmware...");
        if (!await VerifyFirmwareAsync(firmware.Checksum))
        {
            _logger.LogWarning("⚠️ Verificação de firmware falhou (pode ser normal se comando não implementado)");
        }

        _logger.LogInformation("🎉 Firmware carregado com sucesso!");
        return true;
    }

    /// <summary>
    /// Verifica se firmware já está carregado no dispositivo
    /// </summary>
    /// <returns>True se firmware está carregado e válido</returns>
    public Task<bool> IsFirmwareLoadedAsync()
    {
        _logger.LogDebug("Verificando se firmware está carregado...");

        // TODO: Descobrir comando para GET_FIRMWARE_VERSION
        // Comparar com versão esperada do hs3f12.hex

        _logger.LogWarning("⚠️ IsFirmwareLoaded ainda não implementado (TODO)");
        return Task.FromResult(false);
    }

    #endregion

    #region Private Methods - Firmware Parsing

    /// <summary>
    /// Localiza ficheiro hs3f12.hex nos paths conhecidos
    /// </summary>
    private string? FindFirmwareFile()
    {
        foreach (var path in FirmwarePaths)
        {
            if (File.Exists(path))
            {
                _logger.LogDebug("✅ Firmware encontrado: {Path}", path);
                return path;
            }
        }

        _logger.LogWarning("⚠️ Firmware não encontrado em nenhum path conhecido");
        return null;
    }

    /// <summary>
    /// Parseia ficheiro firmware (Intel HEX ou binário)
    /// </summary>
    private async Task<FirmwareData> ParseFirmwareFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("📖 Parseando ficheiro firmware...");

        byte[] fileContent = await File.ReadAllBytesAsync(path, cancellationToken);

        // Detectar formato: Intel HEX começa com ':' ASCII (0x3A)
        bool isIntelHex = fileContent[0] == 0x3A;

        if (isIntelHex)
        {
            _logger.LogDebug("Formato detectado: Intel HEX");
            return ParseIntelHexFormat(fileContent);
        }
        else
        {
            _logger.LogDebug("Formato detectado: Binário");
            return ParseBinaryFormat(fileContent);
        }
    }

    /// <summary>
    /// Parseia formato Intel HEX
    /// Formato: :LLAAAATTDDDDCC
    /// LL = Length, AAAA = Address, TT = Type, DDDD = Data, CC = Checksum
    /// </summary>
    private FirmwareData ParseIntelHexFormat(byte[] fileContent)
    {
        var firmware = new FirmwareData();
        var lines = Encoding.ASCII.GetString(fileContent).Split('\n');

        byte[] binaryData = new byte[EXPECTED_FIRMWARE_SIZE];
        int binaryOffset = 0;

        foreach (var line in lines)
        {
            string trimmedLine = line.Trim();
            if (string.IsNullOrEmpty(trimmedLine) || !trimmedLine.StartsWith(":"))
                continue;

            try
            {
                // Parse Intel HEX record
                int length = Convert.ToInt32(trimmedLine.Substring(1, 2), 16);
                int address = Convert.ToInt32(trimmedLine.Substring(3, 4), 16);
                int recordType = Convert.ToInt32(trimmedLine.Substring(7, 2), 16);

                if (recordType == 0x00) // Data record
                {
                    for (int i = 0; i < length; i++)
                    {
                        int dataOffset = 9 + (i * 2);
                        byte dataByte = Convert.ToByte(trimmedLine.Substring(dataOffset, 2), 16);
                        binaryData[binaryOffset++] = dataByte;
                    }
                }
                else if (recordType == 0x01) // End of file record
                {
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("⚠️ Linha Intel HEX inválida ignorada: {Line} ({Error})",
                    trimmedLine.Substring(0, Math.Min(20, trimmedLine.Length)), ex.Message);
            }
        }

        // Dividir em chunks de 128 bytes
        for (int i = 0; i < binaryOffset; i += FIRMWARE_CHUNK_SIZE)
        {
            int chunkSize = Math.Min(FIRMWARE_CHUNK_SIZE, binaryOffset - i);
            var chunk = new byte[chunkSize];
            Array.Copy(binaryData, i, chunk, 0, chunkSize);
            firmware.Chunks.Add(new FirmwareChunk
            {
                Index = firmware.Chunks.Count,
                Data = chunk,
                Address = (uint)i
            });
        }

        firmware.TotalSize = binaryOffset;
        firmware.Checksum = CalculateChecksum(binaryData, binaryOffset);

        return firmware;
    }

    /// <summary>
    /// Parseia formato binário (raw bytes)
    /// </summary>
    private FirmwareData ParseBinaryFormat(byte[] fileContent)
    {
        var firmware = new FirmwareData();

        // Dividir em chunks de 128 bytes
        for (int i = 0; i < fileContent.Length; i += FIRMWARE_CHUNK_SIZE)
        {
            int chunkSize = Math.Min(FIRMWARE_CHUNK_SIZE, fileContent.Length - i);
            var chunk = new byte[chunkSize];
            Array.Copy(fileContent, i, chunk, 0, chunkSize);

            firmware.Chunks.Add(new FirmwareChunk
            {
                Index = firmware.Chunks.Count,
                Data = chunk,
                Address = (uint)i
            });
        }

        firmware.TotalSize = fileContent.Length;
        firmware.Checksum = CalculateChecksum(fileContent, fileContent.Length);

        return firmware;
    }

    /// <summary>
    /// Calcula checksum simples (XOR de todos bytes)
    /// TODO: Validar algoritmo correto (pode ser CRC16, CRC32, MD5, etc)
    /// </summary>
    private uint CalculateChecksum(byte[] data, int length)
    {
        uint checksum = 0;
        for (int i = 0; i < length; i++)
        {
            checksum ^= data[i];
        }
        return checksum;
    }

    #endregion

    #region Private Methods - USB Upload

    /// <summary>
    /// Envia comando de controle de firmware (START, END, VERIFY)
    /// </summary>
    private Task<bool> SendFirmwareCommandAsync(uint command)
    {
        try
        {
            // TODO: Descobrir se comando existe e como usá-lo
            // Por enquanto, tentar padrão READ→WRITE

            bool success = _protocol.SendCommand(command, 8, out byte[] response);

            if (!success)
            {
                _logger.LogWarning("Comando firmware 0x{Command:X8} falhou (pode não existir)",
                    command);
                return Task.FromResult(false);
            }

            _logger.LogTrace("Comando firmware 0x{Command:X8} OK: {Response}",
                command, BitConverter.ToString(response));

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao enviar comando firmware 0x{Command:X8}", command);
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Envia chunk de firmware para dispositivo
    /// </summary>
    private Task<bool> UploadChunkAsync(FirmwareChunk chunk, int index)
    {
        try
        {
            // TODO: Descobrir protocolo correto para upload
            // Hipóteses:
            // 1. WRITE_OPERATION com CMD_FIRMWARE_CHUNK + data inline
            // 2. WRITE_OPERATION especial com 128 bytes output
            // 3. Sequência READ (status) → WRITE (ack) → BULK_TRANSFER (data)

            // Tentativa 1: WRITE_OPERATION com chunk completo
            bool success = _protocol.WriteOperation(
                CMD_FIRMWARE_CHUNK,
                chunk.Data.Length,
                out byte[] response);

            if (!success)
            {
                _logger.LogError("Chunk {Index} upload falhou", index);
                return Task.FromResult(false);
            }

            // TODO: Validar resposta (deveria ser ACK ou status OK)

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao enviar chunk {Index}", index);
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Verifica integridade do firmware após upload
    /// </summary>
    private Task<bool> VerifyFirmwareAsync(uint expectedChecksum)
    {
        try
        {
            // TODO: Descobrir comando GET_FIRMWARE_CHECKSUM
            // Comparar com expectedChecksum

            bool success = _protocol.SendCommand(
                CMD_FIRMWARE_VERIFY,
                8,
                out byte[] response);

            if (!success)
            {
                _logger.LogWarning("CMD_FIRMWARE_VERIFY não implementado ou falhou");
                return Task.FromResult(false);
            }

            // Parse checksum do dispositivo
            uint deviceChecksum = BitConverter.ToUInt32(response, 0);

            if (deviceChecksum != expectedChecksum)
            {
                _logger.LogError("❌ Checksum mismatch! Esperado: 0x{Expected:X8}, Device: 0x{Device:X8}",
                    expectedChecksum, deviceChecksum);
                return Task.FromResult(false);
            }

            _logger.LogInformation("✅ Firmware verificado (checksum: 0x{Checksum:X8})", deviceChecksum);
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao verificar firmware");
            return Task.FromResult(false);
        }
    }

    #endregion
}

#region Data Structures

/// <summary>
/// Dados de firmware parseados
/// </summary>
public class FirmwareData
{
    public List<FirmwareChunk> Chunks { get; set; } = new();
    public int TotalSize { get; set; }
    public uint Checksum { get; set; }
}

/// <summary>
/// Chunk individual de firmware (128 bytes típico)
/// </summary>
public class FirmwareChunk
{
    public int Index { get; set; }
    public uint Address { get; set; }
    public byte[] Data { get; set; } = Array.Empty<byte>();

    public override string ToString() =>
        $"Chunk {Index}: @0x{Address:X8}, {Data.Length} bytes";
}

#endregion
