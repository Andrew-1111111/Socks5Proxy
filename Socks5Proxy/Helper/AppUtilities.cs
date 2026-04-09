using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Socks5Proxy.Helper
{
    /// <summary>
    /// Prevents multiple instances of an application from running simultaneously.
    /// Cross-platform: uses Mutex on Windows and file-based lock on Unix.
    /// </summary>
    internal sealed class SingleInstanceGuard : IDisposable
    {
        private readonly string _appId;
        private Mutex? _mutex;
        private FileStream? _lockFile;

        private bool _hasLock;

        /// <summary>
        /// Indicates whether the current instance has acquired the lock.
        /// </summary>
        public bool IsRunning { get; private set; }

        /// <summary>
        /// Initializes a new instance of <see cref="SingleInstanceGuard"/>.
        /// </summary>
        /// <param name="appId">Unique identifier for the application.</param>
        public SingleInstanceGuard(string appId)
        {
            if (string.IsNullOrWhiteSpace(appId))
                throw new ArgumentException("Application ID cannot be empty.", nameof(appId));

            _appId = appId;
            _hasLock = AcquireLock();
            IsRunning = !_hasLock;
        }

        /// <summary>
        /// Attempts to acquire the single-instance lock.
        /// </summary>
        /// <returns>True if lock acquired; false if another instance is running.</returns>
        private bool AcquireLock()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _mutex = new Mutex(true, $"Global\\{_appId}", out bool createdNew);
                return createdNew;
            }
            else
            {
                try
                {
                    var tmpPath = Path.Combine(Path.GetTempPath(), $"{_appId}.lock");
                    _lockFile = new FileStream(tmpPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                    return true;
                }
                catch (IOException)
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Releases the single-instance lock.
        /// </summary>
        public void Release()
        {
            if (_mutex != null)
            {
                _mutex.ReleaseMutex();
                _mutex.Dispose();
                _mutex = null;
            }

            if (_lockFile != null)
            {
                _lockFile.Dispose();
                _lockFile = null;
            }

            _hasLock = false;
            IsRunning = false;
        }

        /// <summary>
        /// Disposes the instance and releases any acquired lock.
        /// </summary>
        public void Dispose()
        {
            Release();
            GC.SuppressFinalize(this);
        }
    }
}