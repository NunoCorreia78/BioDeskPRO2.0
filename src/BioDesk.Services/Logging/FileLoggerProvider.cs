using System;
using System.IO;
using System.Text;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Logging;

/// <summary>
/// Logger provider simples que grava mensagens em ficheiro de texto.
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly Func<DateTime, string> _pathFactory;
    private readonly object _syncRoot = new();
    private bool _disposed;

    public FileLoggerProvider(Func<DateTime, string> pathFactory)
    {
        _pathFactory = pathFactory ?? throw new ArgumentNullException(nameof(pathFactory));
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(categoryName, _pathFactory, _syncRoot, () => _disposed);

    public void Dispose()
    {
        _disposed = true;
    }

    private sealed class FileLogger : ILogger
    {
        private readonly string _categoryName;
        private readonly Func<DateTime, string> _pathFactory;
        private readonly object _syncRoot;
        private readonly Func<bool> _isDisposed;

        public FileLogger(string categoryName, Func<DateTime, string> pathFactory, object syncRoot, Func<bool> isDisposed)
        {
            _categoryName = categoryName;
            _pathFactory = pathFactory;
            _syncRoot = syncRoot;
            _isDisposed = isDisposed;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => !_isDisposed() && logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            if (formatter == null)
            {
                throw new ArgumentNullException(nameof(formatter));
            }

            var message = formatter(state, exception);
            if (string.IsNullOrEmpty(message) && exception == null)
            {
                return;
            }

            var timestamp = DateTime.UtcNow;
            var path = _pathFactory(timestamp);

            var builder = new StringBuilder();
            builder.AppendLine($"{timestamp:yyyy-MM-dd HH:mm:ss.fff} [{logLevel}] {_categoryName}: {message}");
            if (exception != null)
            {
                builder.AppendLine(exception.ToString());
            }

            var payload = builder.ToString();

            lock (_syncRoot)
            {
                var directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                File.AppendAllText(path, payload, Encoding.UTF8);
            }
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static NullScope Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}

public static class FileLoggerExtensions
{
    /// <summary>
    /// Adiciona um logger de ficheiro simples ao pipeline de logging.
    /// </summary>
    public static ILoggingBuilder AddFile(this ILoggingBuilder builder, Func<DateTime, string> pathFactory)
    {
        if (builder == null) throw new ArgumentNullException(nameof(builder));
        builder.AddProvider(new FileLoggerProvider(pathFactory));
        return builder;
    }
}
