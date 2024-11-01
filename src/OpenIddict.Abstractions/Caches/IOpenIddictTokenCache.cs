/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to cache tokens after retrieving them from the store.
/// </summary>
/// <typeparam name="TToken">The type of the Token entity.</typeparam>
public interface IOpenIddictTokenCache<TToken> where TToken : class
{
    /// <summary>
    /// Add the specified token to the cache.
    /// </summary>
    /// <param name="token">The token to add to the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask AddAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token, or <see langword="null"/> not to filter out specific subjects.</param>
    /// <param name="client">The client associated with the token, or <see langword="null"/> not to filter out specific clients.</param>
    /// <param name="status">The token status, or <see langword="null"/> not to filter out specific token statuses.</param>
    /// <param name="type">The token type, or <see langword="null"/> not to filter out specific token types.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the criteria.</returns>
    IAsyncEnumerable<TToken> FindAsync(
        string? subject, string? client,
        string? status, string? type, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified application.</returns>
    IAsyncEnumerable<TToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified authorization.</returns>
    IAsyncEnumerable<TToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a token using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the token corresponding to the unique identifier.
    /// </returns>
    ValueTask<TToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified reference identifier.
    /// Note: the reference identifier may be hashed or encrypted for security reasons.
    /// </summary>
    /// <param name="identifier">The reference identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the tokens corresponding to the specified reference identifier.
    /// </returns>
    ValueTask<TToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified subject.</returns>
    IAsyncEnumerable<TToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the specified token from the cache.
    /// </summary>
    /// <param name="token">The token to remove from the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask RemoveAsync(TToken token, CancellationToken cancellationToken);
}
