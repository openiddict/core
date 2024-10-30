/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the authorizations stored in a database.
/// </summary>
/// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
public interface IOpenIddictAuthorizationStore<TAuthorization> where TAuthorization : class
{
    /// <summary>
    /// Determines the number of authorizations that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of authorizations in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Determines the number of authorizations that match the specified query.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of authorizations that match the specified query.
    /// </returns>
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new authorization.
    /// </summary>
    /// <param name="authorization">The authorization to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Removes an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the authorizations corresponding to the specified
    /// subject and associated with the application identifier.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the subject/client.</returns>
    IAsyncEnumerable<TAuthorization> FindAsync(string subject, string client, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="status">The authorization status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the criteria.</returns>
    IAsyncEnumerable<TAuthorization> FindAsync(
        string subject, string client,
        string status, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="status">The authorization status.</param>
    /// <param name="type">The authorization type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the criteria.</returns>
    IAsyncEnumerable<TAuthorization> FindAsync(
        string subject, string client,
        string status, string type, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="status">The authorization status.</param>
    /// <param name="type">The authorization type.</param>
    /// <param name="scopes">The minimal scopes associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the criteria.</returns>
    IAsyncEnumerable<TAuthorization> FindAsync(
        string subject, string client,
        string status, string type,
        ImmutableArray<string> scopes, CancellationToken cancellationToken);

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
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
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
    /// Retrieves the optional application identifier associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the authorization.
    /// </returns>
    ValueTask<string?> GetApplicationIdAsync(TAuthorization authorization, CancellationToken cancellationToken);

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
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the creation date associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified authorization.
    /// </returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the unique identifier associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the authorization.
    /// </returns>
    ValueTask<string?> GetIdAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the authorization.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the scopes associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the scopes associated with the specified authorization.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetScopesAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the status associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified authorization.
    /// </returns>
    ValueTask<string?> GetStatusAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the subject associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified authorization.
    /// </returns>
    ValueTask<string?> GetSubjectAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the type associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the type associated with the specified authorization.
    /// </returns>
    ValueTask<string?> GetTypeAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Instantiates a new authorization.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the instantiated authorization, that can be persisted in the database.
    /// </returns>
    ValueTask<TAuthorization> InstantiateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TAuthorization> ListAsync(int? count, int? offset, CancellationToken cancellationToken);

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
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the authorizations that are marked as invalid and the ad-hoc ones that have no token attached.
    /// Only authorizations created before the specified <paramref name="threshold"/> are removed.
    /// </summary>
    /// <remarks>
    /// To ensure ad-hoc authorizations that no longer have any valid/non-expired token
    /// attached are correctly removed, the tokens should always be pruned first.
    /// </remarks>
    /// <param name="threshold">The date before which authorizations are not pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations that were removed.</returns>
    ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the authorizations corresponding to the specified
    /// subject and associated with the application identifier.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string subject, string client, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="status">The authorization status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string subject, string client, string status, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="status">The authorization status.</param>
    /// <param name="type">The authorization type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string subject, string client, string status, string type, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all the authorizations associated with the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations associated with the specified application that were marked as revoked.</returns>
    ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all the authorizations associated with the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations associated with the specified subject that were marked as revoked.</returns>
    ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets the application identifier associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="identifier">The unique identifier associated with the client application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetApplicationIdAsync(TAuthorization authorization, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the creation date associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="date">The expiration date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetCreationDateAsync(TAuthorization authorization, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the additional properties associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="properties">The additional properties associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPropertiesAsync(TAuthorization authorization,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the scopes associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="scopes">The scopes associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetScopesAsync(TAuthorization authorization,
        ImmutableArray<string> scopes, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the status associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="status">The status associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetStatusAsync(TAuthorization authorization, string? status, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the subject associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetSubjectAsync(TAuthorization authorization, string? subject, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the type associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="type">The type associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetTypeAsync(TAuthorization authorization, string? type, CancellationToken cancellationToken);

    /// <summary>
    /// Updates an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(TAuthorization authorization, CancellationToken cancellationToken);
}
