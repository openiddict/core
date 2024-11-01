/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to cache authorizations after retrieving them from the store.
/// </summary>
/// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
public interface IOpenIddictAuthorizationCache<TAuthorization> where TAuthorization : class
{
    /// <summary>
    /// Add the specified authorization to the cache.
    /// </summary>
    /// <param name="authorization">The authorization to add to the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask AddAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization, or <see langword="null"/> not to filter out specific subjects.</param>
    /// <param name="client">The client associated with the authorization, or <see langword="null"/> not to filter out specific clients.</param>
    /// <param name="status">The authorization status, or <see langword="null"/> not to filter out specific authorization statuses.</param>
    /// <param name="type">The authorization type, or <see langword="null"/> not to filter out specific authorization types.</param>
    /// <param name="scopes">The minimal scopes associated with the authorization, or <see langword="null"/> not to filter out scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the criteria.</returns>
    IAsyncEnumerable<TAuthorization> FindAsync(
        string? subject, string? client, string? status,
        string? type, ImmutableArray<string>? scopes, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of authorizations corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified application.</returns>
    IAsyncEnumerable<TAuthorization> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves an authorization using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization corresponding to the identifier.
    /// </returns>
    ValueTask<TAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all the authorizations corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified subject.</returns>
    IAsyncEnumerable<TAuthorization> FindBySubjectAsync(string subject, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the specified authorization from the cache.
    /// </summary>
    /// <param name="authorization">The authorization to remove from the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask RemoveAsync(TAuthorization authorization, CancellationToken cancellationToken);
}
