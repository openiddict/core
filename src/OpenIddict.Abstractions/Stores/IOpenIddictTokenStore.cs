/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TToken">The type of the Token entity.</typeparam>
public interface IOpenIddictTokenStore<TToken> where TToken : class
{
    /// <summary>
    /// Determines the number of tokens that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of applications in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

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
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new token.
    /// </summary>
    /// <param name="token">The token to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Removes a token.
    /// </summary>
    /// <param name="token">The token to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the tokens corresponding to the specified
    /// subject and associated with the application identifier.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the subject/client.</returns>
    IAsyncEnumerable<TToken> FindAsync(string subject, string client, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the criteria.</returns>
    IAsyncEnumerable<TToken> FindAsync(
        string subject, string client,
        string status, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="type">The token type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the criteria.</returns>
    IAsyncEnumerable<TToken> FindAsync(
        string subject, string client,
        string status, string type, CancellationToken cancellationToken);

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
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
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
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
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
    /// Retrieves the optional application identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the token.
    /// </returns>
    ValueTask<string?> GetApplicationIdAsync(TToken token, CancellationToken cancellationToken);

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
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the optional authorization identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization identifier associated with the token.
    /// </returns>
    ValueTask<string?> GetAuthorizationIdAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the creation date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified token.
    /// </returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the expiration date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the expiration date associated with the specified token.
    /// </returns>
    ValueTask<DateTimeOffset?> GetExpirationDateAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the unique identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the token.
    /// </returns>
    ValueTask<string?> GetIdAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the payload associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the payload associated with the specified token.
    /// </returns>
    ValueTask<string?> GetPayloadAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the token.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the redemption date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the redemption date associated with the specified token.
    /// </returns>
    ValueTask<DateTimeOffset?> GetRedemptionDateAsync(TToken token, CancellationToken cancellationToken);

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
    ValueTask<string?> GetReferenceIdAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the status associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified token.
    /// </returns>
    ValueTask<string?> GetStatusAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the subject associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified token.
    /// </returns>
    ValueTask<string?> GetSubjectAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the token type associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the token type associated with the specified token.
    /// </returns>
    ValueTask<string?> GetTypeAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Instantiates a new token.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the instantiated token, that can be persisted in the database.
    /// </returns>
    ValueTask<TToken> InstantiateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TToken> ListAsync(int? count, int? offset, CancellationToken cancellationToken);

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
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the tokens that are marked as invalid or whose attached authorization is no longer valid.
    /// Only tokens created before the specified <paramref name="threshold"/> are removed.
    /// </summary>
    /// <param name="threshold">The date before which tokens are not pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens that were removed.</returns>
    ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the tokens corresponding to the specified
    /// subject and associated with the application identifier.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string subject, string client, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string subject, string client, string status, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="type">The token type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string subject, string client, string status, string type, CancellationToken cancellationToken);

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
    ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the tokens associated with the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens associated with the specified subject that were marked as revoked.</returns>
    ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets the application identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="identifier">The unique identifier associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetApplicationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the authorization identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="identifier">The unique identifier associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetAuthorizationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the creation date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="date">The creation date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetCreationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the expiration date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="date">The expiration date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetExpirationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the payload associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="payload">The payload associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPayloadAsync(TToken token, string? payload, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the additional properties associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="properties">The additional properties associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPropertiesAsync(TToken token,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the redemption date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="date">The redemption date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetRedemptionDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the reference identifier associated with a token.
    /// Note: depending on the manager used to create the token,
    /// the reference identifier may be hashed for security reasons.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="identifier">The reference identifier associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetReferenceIdAsync(TToken token, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the status associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="status">The status associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetStatusAsync(TToken token, string? status, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the subject associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetSubjectAsync(TToken token, string? subject, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the token type associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="type">The token type associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetTypeAsync(TToken token, string? type, CancellationToken cancellationToken);

    /// <summary>
    /// Updates an existing token.
    /// </summary>
    /// <param name="token">The token to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(TToken token, CancellationToken cancellationToken);
}
