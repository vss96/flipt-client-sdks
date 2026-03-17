using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using FliptClient.Models;

namespace FliptClient
{
    /// <summary>
    /// Main client for interacting with the Flipt feature flag engine.
    /// </summary>
    public class FliptClient : IDisposable
    {
        private static readonly TimeSpan ExpiryBuffer = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan MinRetryDelay = TimeSpan.FromSeconds(5);

        private readonly IAuthenticationProvider? _authenticationProvider;
        private readonly int _maxAuthRetries;
        private IntPtr _engine;
        private int _consecutiveAuthFailures;
        private DateTimeOffset? _currentExpiry;
        private Timer? _authRefreshTimer;
        private int _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="FliptClient"/> class.
        /// </summary>
        /// <param name="options">Client options, including configuration.</param>
        /// <exception cref="ValidationException">Thrown if options are invalid.</exception>
        public FliptClient(ClientOptions options)
        {
            if (options == null)
            {
                throw new ValidationException("ClientOptions cannot be null");
            }

#pragma warning disable CS0618 // Suppress obsolete warning for internal usage
            if (options.Authentication != null && options.AuthenticationProvider != null)
            {
                throw new ValidationException("Cannot set both Authentication and AuthenticationProvider");
            }

            _authenticationProvider = options.AuthenticationProvider;

            if (_authenticationProvider != null)
            {
                AuthenticationLease initial = _authenticationProvider.Get();
                options.Authentication = initial.Strategy;
                _currentExpiry = initial.ExpiresAt;
                _maxAuthRetries = initial.MaxRetries ?? 0;
            }
#pragma warning restore CS0618

            string optsJson = JsonSerializer.Serialize(options);
            _engine = NativeMethods.InitializeEngine(optsJson);

            // Start auth refresh timer only for expiring leases
            if (_authenticationProvider != null && _currentExpiry != null)
            {
                ScheduleNextAuthRefresh();
            }
        }

        /// <summary>
        /// Evaluates a variant flag for the given entity and context.
        /// </summary>
        /// <returns>The variant evaluation response.</returns>
        public VariantEvaluationResponse? EvaluateVariant(string flagKey, string entityId, Dictionary<string, string> context)
        {
            if (string.IsNullOrWhiteSpace(flagKey))
            {
                throw new ValidationException("flagKey cannot be empty or null");
            }

            if (string.IsNullOrWhiteSpace(entityId))
            {
                throw new ValidationException("entityId cannot be empty or null");
            }

            if (context == null)
            {
                context = new Dictionary<string, string>();
            }

            var request = new EvaluationRequest
            {
                FlagKey = flagKey,
                EntityId = entityId,
                Context = context
            };
            string requestJson = JsonSerializer.Serialize(request);
            IntPtr resultPtr = NativeMethods.EvaluateVariant(_engine, requestJson);
            string resultJson = Marshal.PtrToStringAnsi(resultPtr) ?? throw new FliptException("Failed to get result from native code");
            NativeMethods.DestroyString(resultPtr);
            var result = JsonSerializer.Deserialize<VariantResult>(resultJson) ?? throw new EvaluationException("Failed to deserialize response");
            if (result.Status != "success")
            {
                throw new EvaluationException(result.ErrorMessage ?? "Unknown error");
            }

            return result.Response;
        }

        /// <summary>
        /// Evaluates a boolean flag for the given entity and context.
        /// </summary>
        /// <returns>The boolean evaluation response.</returns>
        public BooleanEvaluationResponse? EvaluateBoolean(string flagKey, string entityId, Dictionary<string, string> context)
        {
            if (string.IsNullOrWhiteSpace(flagKey))
            {
                throw new ValidationException("flagKey cannot be empty or null");
            }

            if (string.IsNullOrWhiteSpace(entityId))
            {
                throw new ValidationException("entityId cannot be empty or null");
            }

            if (context == null)
            {
                context = new Dictionary<string, string>();
            }

            var request = new EvaluationRequest
            {
                FlagKey = flagKey,
                EntityId = entityId,
                Context = context
            };
            string requestJson = JsonSerializer.Serialize(request);
            IntPtr resultPtr = NativeMethods.EvaluateBoolean(_engine, requestJson);
            string resultJson = Marshal.PtrToStringAnsi(resultPtr) ?? throw new FliptException("Failed to get result from native code");
            NativeMethods.DestroyString(resultPtr);
            var result = JsonSerializer.Deserialize<BooleanResult>(resultJson) ?? throw new EvaluationException("Failed to deserialize response");
            if (result.Status != "success")
            {
                throw new EvaluationException(result.ErrorMessage ?? "Unknown error");
            }

            return result.Response;
        }

        /// <summary>
        /// Evaluates a batch of flag requests.
        /// </summary>
        /// <returns>The batch evaluation response.</returns>
        public BatchEvaluationResponse? EvaluateBatch(List<EvaluationRequest> requests)
        {
            if (requests == null || requests.Count == 0)
            {
                throw new ValidationException("requests cannot be empty or null");
            }

            string requestJson = JsonSerializer.Serialize(requests);
            IntPtr resultPtr = NativeMethods.EvaluateBatch(_engine, requestJson);
            string resultJson = Marshal.PtrToStringAnsi(resultPtr) ?? throw new FliptException("Failed to get result from native code");
            NativeMethods.DestroyString(resultPtr);
            var result = JsonSerializer.Deserialize<BatchResult>(resultJson) ?? throw new EvaluationException("Failed to deserialize response");
            if (result.Status != "success")
            {
                throw new EvaluationException(result.ErrorMessage ?? "Unknown error");
            }

            return result.Response;
        }

        /// <summary>
        /// Lists all flags in the current namespace.
        /// </summary>
        /// <returns>Array of flags.</returns>
        public Flag[]? ListFlags()
        {
            IntPtr resultPtr = NativeMethods.ListFlags(_engine);
            string resultJson = Marshal.PtrToStringAnsi(resultPtr) ?? throw new FliptException("Failed to get result from native code");
            NativeMethods.DestroyString(resultPtr);
            var result = JsonSerializer.Deserialize<ListFlagsResult>(resultJson) ?? throw new EvaluationException("Failed to deserialize response");
            if (result.Status != "success")
            {
                throw new EvaluationException(result.ErrorMessage ?? "Unknown error");
            }

            return result.Response;
        }

        /// <summary>
        /// Gets the snapshot for the client.
        /// </summary>
        /// <returns>The snapshot string.</returns>
        public string? GetSnapshot()
        {
            IntPtr resultPtr = NativeMethods.GetSnapshot(_engine);
            string resultStr = Marshal.PtrToStringAnsi(resultPtr) ?? throw new FliptException("Failed to get result from native code");
            NativeMethods.DestroyString(resultPtr);
            return resultStr;
        }

        /// <summary>
        /// Disposes the client and releases native resources.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            {
                return;
            }

            _authRefreshTimer?.Dispose();
            _authRefreshTimer = null;

            if (_engine != IntPtr.Zero)
            {
                NativeMethods.DestroyEngine(_engine);
                _engine = IntPtr.Zero;
            }
        }

        private void ScheduleNextAuthRefresh()
        {
            if (Volatile.Read(ref _disposed) != 0 || _currentExpiry == null)
            {
                return;
            }

            TimeSpan delay = _currentExpiry.Value - ExpiryBuffer - DateTimeOffset.UtcNow;
            if (delay <= TimeSpan.Zero)
            {
                delay = MinRetryDelay;
            }

            _authRefreshTimer?.Dispose();
            _authRefreshTimer = new Timer(OnAuthRefresh, null, delay, Timeout.InfiniteTimeSpan);
        }

        private void OnAuthRefresh(object? state)
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            try
            {
                AuthenticationLease lease = _authenticationProvider!.Get();

                if (Volatile.Read(ref _disposed) != 0)
                {
                    return;
                }

                string authJson = JsonSerializer.Serialize(lease.Strategy);
                IntPtr resultPtr = NativeMethods.UpdateAuthentication(_engine, authJson);
                string resultJson = Marshal.PtrToStringAnsi(resultPtr) ?? throw new FliptException("Failed to get result from native code");
                NativeMethods.DestroyString(resultPtr);

                var result = JsonSerializer.Deserialize<UpdateAuthResult>(resultJson);
                if (result != null && result.Status == "success")
                {
                    Interlocked.Exchange(ref _consecutiveAuthFailures, 0);
                    _currentExpiry = lease.ExpiresAt;
                }
                else
                {
                    Interlocked.Increment(ref _consecutiveAuthFailures);
                    string errorMsg = result?.ErrorMessage ?? "Unknown error";
                    System.Diagnostics.Trace.TraceWarning($"Failed to update engine authentication: {errorMsg}");
                }
            }
            catch (Exception e)
            {
                Interlocked.Increment(ref _consecutiveAuthFailures);
                System.Diagnostics.Trace.TraceWarning($"Failed to refresh authentication: {e.Message}");
            }

            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            if (_currentExpiry == null)
            {
                return;
            }

            if (Volatile.Read(ref _consecutiveAuthFailures) >= _maxAuthRetries)
            {
                System.Diagnostics.Trace.TraceError($"Authentication refresh failed after {_maxAuthRetries} consecutive attempts, stopping refresh");
                return;
            }

            ScheduleNextAuthRefresh();
        }
    }

    /// <summary>
    /// Base exception for Flipt client errors.
    /// </summary>
    public class FliptException : Exception
    {
        public FliptException(string message)
            : base(message)
        {
        }
    }

    /// <summary>
    /// Exception for validation errors.
    /// </summary>
    public class ValidationException : FliptException
    {
        public ValidationException(string message)
            : base(message)
        {
        }
    }

    /// <summary>
    /// Exception for evaluation errors.
    /// </summary>
    public class EvaluationException : FliptException
    {
        public EvaluationException(string message)
            : base(message)
        {
        }
    }
}
