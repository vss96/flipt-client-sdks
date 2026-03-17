namespace FliptClient.Models
{
    /// <summary>
    /// A provider for authentication credentials that supports token refresh.
    /// Implement this interface to provide dynamic authentication tokens that can
    /// be refreshed when they expire.
    /// </summary>
    public interface IAuthenticationProvider
    {
        /// <summary>
        /// Returns the current authentication credentials and their expiry time.
        /// </summary>
        /// <returns>An <see cref="AuthenticationLease"/> containing the credential and expiry.</returns>
        AuthenticationLease Get();
    }
}
