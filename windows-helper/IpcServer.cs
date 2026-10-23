using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace QRShieldHelper
{
    public class IpcServer : IDisposable
    {
        public const string PipeName = "QRShieldPipe";

        private NamedPipeServerStream _pipeStream;
        private StreamWriter _writer;
        private StreamReader _reader;
        private Thread _listenThread;
        private bool _isRunning;
        private readonly object _sendLock = new object();

        public event Action<string> MessageReceived;
        public event Action ClientConnected;
        public event Action ClientDisconnected;

        public bool IsClientConnected
        {
            get { return _pipeStream != null && _pipeStream.IsConnected; }
        }

        public IpcServer()
        {
            _isRunning = false;
        }

        public void Start()
        {
            _isRunning = true;
            _listenThread = new Thread(ListenLoop);
            _listenThread.IsBackground = true;
            _listenThread.Name = "QRShieldPipeServerThread";
            _listenThread.Start();
        }

        private void ListenLoop()
        {
            while (_isRunning)
            {
                try
                {
                    // Restrict Named Pipe to current local user session for security
                    PipeSecurity pipeSecurity = new PipeSecurity();
                    SecurityIdentifier currentUserId = WindowsIdentity.GetCurrent().User;
                    if (currentUserId != null)
                    {
                        pipeSecurity.AddAccessRule(new PipeAccessRule(
                            currentUserId,
                            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                            AccessControlType.Allow));
                    }

                    _pipeStream = new NamedPipeServerStream(
                        PipeName,
                        PipeDirection.InOut,
                        1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        4096,
                        4096,
                        pipeSecurity);

                    _pipeStream.WaitForConnection();

                    _reader = new StreamReader(_pipeStream, Encoding.UTF8);
                    _writer = new StreamWriter(_pipeStream, Encoding.UTF8);
                    _writer.AutoFlush = true;

                    if (ClientConnected != null) ClientConnected();

                    while (_isRunning && _pipeStream.IsConnected)
                    {
                        string line = _reader.ReadLine();
                        if (line == null) break; // Client disconnected

                        if (MessageReceived != null) MessageReceived(line);
                    }
                }
                catch (Exception)
                {
                    // Connection closed or interrupted
                }
                finally
                {
                    if (ClientDisconnected != null) ClientDisconnected();
                    CleanupCurrentConnection();
                }

                if (_isRunning)
                {
                    Thread.Sleep(500); // Brief delay before accepting next connection
                }
            }
        }

        public void SendJson(string json)
        {
            lock (_sendLock)
            {
                try
                {
                    if (_writer != null && _pipeStream != null && _pipeStream.IsConnected)
                    {
                        _writer.WriteLine(json);
                    }
                }
                catch { }
            }
        }

        private void CleanupCurrentConnection()
        {
            try
            {
                if (_reader != null) _reader.Dispose();
                if (_writer != null) _writer.Dispose();
                if (_pipeStream != null) _pipeStream.Dispose();
            }
            catch { }
            _reader = null;
            _writer = null;
            _pipeStream = null;
        }

        public void Dispose()
        {
            _isRunning = false;
            CleanupCurrentConnection();
            try
            {
                if (_listenThread != null) _listenThread.Abort();
            }
            catch { }
        }
    }
}
