/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the tokens stored in the store.
/// Note: this interface is not meant to be implemented by custom managers,
/// that should inherit from the generic OpenIddictTokenManager class.
/// It is primarily intended to be used by services that cannot easily
/// depend on the generic token manager. The actual token entity type is
/// automatically determined at runtime based on the OpenIddict core options.
/// </summary>
public interface IOpenIddictTokenManager
{
    /// <summary>
    /// Determines the number of tokens that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of tokens in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines the number of tokens that match the specified query.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of tokens that match the specified query.
    /// </returns>
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new token based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The token descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the token.
    /// </returns>
    ValueTask<object> CreateAsync(OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask CreateAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an existing token.
    /// </summary>
    /// <param name="token">The token to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask DeleteAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token, or <see langword="null"/> not to filter out specific subjects.</param>
    /// <param name="client">The client associated with the token, or <see langword="null"/> not to filter out specific clients.</param>
    /// <param name="status">The token status, or <see langword="null"/> not to filter out specific token statuses.</param>
    /// <param name="type">The token type, or <see langword="null"/> not to filter out specific token types.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the criteria.</returns>
    IAsyncEnumerable<object> FindAsync(
        string? subject, string? client,
        string? status, string? type, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified application.</returns>
    IAsyncEnumerable<object> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified authorization.</returns>
    IAsyncEnumerable<object> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a token using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the token corresponding to the unique identifier.
    /// </returns>
    ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified reference identifier.
    /// Note: the reference identifier may be hashed or encrypted for security reasons.
    /// </summary>
    /// <param name="identifier">The reference identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the tokens corresponding to the specified reference identifier.
    /// </returns>
    ValueTask<object?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified subject.</returns>
    IAsyncEnumerable<object> FindBySubjectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the optional application identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the token.
    /// </returns>
    ValueTask<string?> GetApplicationIdAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    ValueTask<TResult?> GetAsync<TResult>(
        Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<object>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the optional authorization identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization identifier associated with the token.
    /// </returns>
    ValueTask<string?> GetAuthorizationIdAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the creation date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified token.
    /// </returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the expiration date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the expiration date associated with the specified token.
    /// </returns>
    ValueTask<DateTimeOffset?> GetExpirationDateAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the unique identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the token.
    /// </returns>
    ValueTask<string?> GetIdAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the payload associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the payload associated with the specified token.
    /// </returns>
    ValueTask<string?> GetPayloadAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the additional properties associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the token.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the redemption date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the redemption date associated with the specified token.
    /// </returns>
    ValueTask<DateTimeOffset?> GetRedemptionDateAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the reference identifier associated with a token.
    /// Note: depending on the manager used to create the token,
    /// the reference identifier may be hashed for security reasons.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the reference identifier associated with the specified token.
    /// </returns>
    ValueTask<string?> GetReferenceIdAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the status associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified token.
    /// </returns>
    ValueTask<string?> GetStatusAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the subject associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified token.
    /// </returns>
    ValueTask<string?> GetSubjectAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the token type associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the token type associated with the specified token.
    /// </returns>
    ValueTask<string?> GetTypeAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given token has the specified status.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="status">The expected status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token has the specified status, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> HasStatusAsync(object token, string status, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given token has the specified type.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="type">The expected type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token has the specified type, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> HasTypeAsync(object token, string type, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given token has any of the specified types.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="types">The expected types.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token has any of the specified types, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> HasTypeAsync(object token, ImmutableArray<string> types, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<object> ListAsync(
        int? count = null, int? offset = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TResult> ListAsync<TResult>(
        Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<object>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the token.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(OpenIddictTokenDescriptor descriptor, object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the token using the specified descriptor.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(object token, OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the tokens that are marked as invalid or whose attached authorization is no longer valid.
    /// Only tokens created before the specified <paramref name="threshold"/> are removed.
    /// </summary>
    /// <param name="threshold">The date before which tokens are not pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens that were removed.</returns>
    ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token, or <see langword="null"/> not to filter out specific subjects.</param>
    /// <param name="client">The client associated with the token, or <see langword="null"/> not to filter out specific clients.</param>
    /// <param name="status">The token status, or <see langword="null"/> not to filter out specific token statuses.</param>
    /// <param name="type">The token type, or <see langword="null"/> not to filter out specific token types.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all the tokens associated with the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens associated with the specified application that were marked as revoked.</returns>
    ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all the tokens associated with the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens associated with the specified authorization that were marked as revoked.</returns>
    ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all the tokens associated with the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens associated with the specified subject that were marked as revoked.</returns>
    ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries to redeem a token.
    /// </summary>
    /// <param name="token">The token to redeem.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token was successfully redemeed, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> TryRedeemAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries to reject a token.
    /// </summary>
    /// <param name="token">The token to reject.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token was successfully redemeed, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> TryRejectAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries to revoke a token.
    /// </summary>
    /// <param name="token">The token to revoke.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token was successfully revoked, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> TryRevokeAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing token.
    /// </summary>
    /// <param name="token">The token to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing token.
    /// </summary>
    /// <param name="token">The token to update.</param>
    /// <param name="descriptor">The descriptor used to update the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object token, OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the token to ensure it's in a consistent state.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the token.</returns>
    IAsyncEnumerable<ValidationResult> ValidateAsync(object token, CancellationToken cancellationToken = default);
}
