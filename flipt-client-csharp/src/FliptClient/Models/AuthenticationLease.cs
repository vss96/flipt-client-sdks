using System;

namespace FliptClient.Models
{
    /// <summary>
    /// An authentication credential with an optional expiry time.
    /// Use the fluent builder to create instances:
    /// <code>
    /// // Expiring lease (triggers refresh before expiry)
    /// AuthenticationLease.Expiring(expiresAt).Jwt(token).Build()
    /// AuthenticationLease.Expiring(expiresAt).Jwt(token).MaxRetries(3).Build()
    ///
    /// // Fixed lease (no expiry, no refresh scheduling)
    /// AuthenticationLease.Fixed().ClientToken(token).Build()
    /// </code>
    /// </summary>
    public class AuthenticationLease
    {
        private const int DefaultMaxRetries = 5;

        private AuthenticationLease(Authentication strategy, DateTimeOffset? expiresAt, int? maxRetries)
        {
            if (strategy == null)
            {
                throw new ArgumentNullException(nameof(strategy), "strategy cannot be null");
            }

            Strategy = strategy;
            ExpiresAt = expiresAt;
            MaxRetries = maxRetries;
        }

        /// <summary>
        /// Gets the authentication strategy for this lease.
        /// </summary>
        public Authentication Strategy { get; }

        /// <summary>
        /// Gets the expiry time of this lease, or null if the lease does not expire.
        /// </summary>
        public DateTimeOffset? ExpiresAt { get; }

        /// <summary>
        /// Gets the maximum number of consecutive refresh retries, or null for fixed leases.
        /// </summary>
        public int? MaxRetries { get; }

        /// <summary>
        /// Starts building a fixed lease with no expiry. No refresh will be scheduled.
        /// </summary>
        /// <returns>A builder to select the authentication type.</returns>
        public static FixedBuilder Fixed()
        {
            return new FixedBuilder();
        }

        /// <summary>
        /// Starts building an expiring lease that triggers a refresh before the given expiry time.
        /// </summary>
        /// <param name="expiresAt">When this credential expires.</param>
        /// <returns>A builder to select the authentication type and configure retries.</returns>
        public static ExpiringBuilder Expiring(DateTimeOffset expiresAt)
        {
            return new ExpiringBuilder(expiresAt);
        }

        /// <summary>
        /// Builder for fixed leases (no expiry, no retries).
        /// </summary>
        public class FixedBuilder
        {
            internal FixedBuilder()
            {
            }

            /// <summary>
            /// Sets JWT authentication for this lease.
            /// </summary>
            /// <param name="token">The JWT token value.</param>
            /// <returns>The build step to finalize the lease.</returns>
            public FixedBuildStep Jwt(string token)
            {
                return new FixedBuildStep(new Authentication { JwtToken = token });
            }

            /// <summary>
            /// Sets client token authentication for this lease.
            /// </summary>
            /// <param name="token">The client token value.</param>
            /// <returns>The build step to finalize the lease.</returns>
            public FixedBuildStep ClientToken(string token)
            {
                return new FixedBuildStep(new Authentication { ClientToken = token });
            }
        }

        /// <summary>
        /// Final build step for fixed leases.
        /// </summary>
        public class FixedBuildStep
        {
            private readonly Authentication _strategy;

            internal FixedBuildStep(Authentication strategy)
            {
                _strategy = strategy;
            }

            /// <summary>
            /// Builds the fixed authentication lease.
            /// </summary>
            /// <returns>A new AuthenticationLease.</returns>
            public AuthenticationLease Build()
            {
                return new AuthenticationLease(_strategy, null, null);
            }
        }

        /// <summary>
        /// Builder for expiring leases.
        /// </summary>
        public class ExpiringBuilder
        {
            private readonly DateTimeOffset _expiresAt;

            internal ExpiringBuilder(DateTimeOffset expiresAt)
            {
                _expiresAt = expiresAt;
            }

            /// <summary>
            /// Sets JWT authentication for this lease.
            /// </summary>
            /// <param name="token">The JWT token value.</param>
            /// <returns>The build step to configure retries and finalize the lease.</returns>
            public ExpiringBuildStep Jwt(string token)
            {
                return new ExpiringBuildStep(new Authentication { JwtToken = token }, _expiresAt);
            }

            /// <summary>
            /// Sets client token authentication for this lease.
            /// </summary>
            /// <param name="token">The client token value.</param>
            /// <returns>The build step to configure retries and finalize the lease.</returns>
            public ExpiringBuildStep ClientToken(string token)
            {
                return new ExpiringBuildStep(new Authentication { ClientToken = token }, _expiresAt);
            }
        }

        /// <summary>
        /// Final build step for expiring leases with configurable retries.
        /// </summary>
        public class ExpiringBuildStep
        {
            private readonly Authentication _strategy;
            private readonly DateTimeOffset _expiresAt;
            private int _maxRetries = DefaultMaxRetries;

            internal ExpiringBuildStep(Authentication strategy, DateTimeOffset expiresAt)
            {
                _strategy = strategy;
                _expiresAt = expiresAt;
            }

            /// <summary>
            /// Sets the maximum number of consecutive refresh failures before stopping. Defaults to 5.
            /// </summary>
            /// <param name="maxRetries">The maximum number of retries (must be non-negative).</param>
            /// <returns>This build step.</returns>
            public ExpiringBuildStep MaxRetries(int maxRetries)
            {
                if (maxRetries < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(maxRetries), "maxRetries must be non-negative");
                }

                _maxRetries = maxRetries;
                return this;
            }

            /// <summary>
            /// Builds the expiring authentication lease.
            /// </summary>
            /// <returns>A new AuthenticationLease.</returns>
            public AuthenticationLease Build()
            {
                return new AuthenticationLease(_strategy, _expiresAt, _maxRetries);
            }
        }
    }
}
