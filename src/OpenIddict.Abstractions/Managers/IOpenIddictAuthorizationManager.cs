/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the authorizations stored in the store.
/// Note: this interface is not meant to be implemented by custom managers,
/// that should inherit from the generic OpenIddictAuthorizationManager class.
/// It is primarily intended to be used by services that cannot easily depend
/// on the generic authorization manager. The actual authorization entity type
/// is automatically determined at runtime based on the OpenIddict core options.
/// </summary>
public interface IOpenIddictAuthorizationManager
{
    /// <summary>
    /// Determines the number of authorizations that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of authorizations in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken = default);

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
    ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new permanent authorization based on the specified parameters.
    /// </summary>
    /// <param name="identity">The identity associated with the authorization.</param>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="type">The authorization type.</param>
    /// <param name="scopes">The minimal scopes associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the authorization.
    /// </returns>
    ValueTask<object> CreateAsync(
        ClaimsIdentity identity, string subject, string client,
        string type, ImmutableArray<string> scopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new permanent authorization based on the specified parameters.
    /// </summary>
    /// <param name="principal">The principal associated with the authorization.</param>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="client">The client associated with the authorization.</param>
    /// <param name="type">The authorization type.</param>
    /// <param name="scopes">The minimal scopes associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the authorization.
    /// </returns>
    ValueTask<object> CreateAsync(
        ClaimsPrincipal principal, string subject, string client,
        string type, ImmutableArray<string> scopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new authorization based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The authorization descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the authorization.
    /// </returns>
    ValueTask<object> CreateAsync(OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new authorization.
    /// </summary>
    /// <param name="authorization">The application to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask CreateAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask DeleteAsync(object authorization, CancellationToken cancellationToken = default);

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
    IAsyncEnumerable<object> FindAsync(
        string? subject, string? client, string? status,
        string? type, ImmutableArray<string>? scopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of authorizations corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified application.</returns>
    IAsyncEnumerable<object> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves an authorization using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization corresponding to the identifier.
    /// </returns>
    ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all the authorizations corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified subject.</returns>
    IAsyncEnumerable<object> FindBySubjectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the optional application identifier associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the authorization.
    /// </returns>
    ValueTask<string?> GetApplicationIdAsync(object authorization, CancellationToken cancellationToken = default);

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
    /// Retrieves the creation date associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified authorization.
    /// </returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the unique identifier associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the authorization.
    /// </returns>
    ValueTask<string?> GetIdAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the additional properties associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the authorization.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the scopes associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the scopes associated with the specified authorization.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetScopesAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the status associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified authorization.
    /// </returns>
    ValueTask<string?> GetStatusAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the subject associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified authorization.
    /// </returns>
    ValueTask<string?> GetSubjectAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the type associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the type associated with the specified authorization.
    /// </returns>
    ValueTask<string?> GetTypeAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether the specified scopes are included in the authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="scopes">The scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the scopes are included in the authorization, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> HasScopesAsync(object authorization, ImmutableArray<string> scopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given authorization has the specified status.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="status">The expected status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authorization has the specified status, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> HasStatusAsync(object authorization, string status, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given authorization has the specified type.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="type">The expected type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authorization has the specified type, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> HasTypeAsync(object authorization, string type, CancellationToken cancellationToken = default);

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
    /// Populates the specified descriptor using the properties exposed by the authorization.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(OpenIddictAuthorizationDescriptor descriptor, object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the authorization using the specified descriptor.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(object authorization, OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the authorizations that are marked as invalid and don't have any token attached.
    /// Only authorizations created before the specified <paramref name="threshold"/> are removed.
    /// </summary>
    /// <remarks>
    /// Since authorizations with tokens still attached are not deleted, tokens should always be pruned first.
    /// </remarks>
    /// <param name="threshold">The date before which authorizations are not pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations that were removed.</returns>
    ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization, or <see langword="null"/> not to filter out specific subjects.</param>
    /// <param name="client">The client associated with the authorization, or <see langword="null"/> not to filter out specific clients.</param>
    /// <param name="status">The authorization status, or <see langword="null"/> not to filter out specific authorization statuses.</param>
    /// <param name="type">The authorization type, or <see langword="null"/> not to filter out specific authorization types.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations corresponding to the criteria that were marked as revoked.</returns>
    ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken = default);

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
    /// Tries to revoke an authorization.
    /// </summary>
    /// <param name="authorization">The authorization to revoke.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authorization was successfully revoked, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> TryRevokeAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object authorization, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to update.</param>
    /// <param name="descriptor">The descriptor used to update the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object authorization, OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the authorization to ensure it's in a consistent state.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the authorization.</returns>
    IAsyncEnumerable<ValidationResult> ValidateAsync(object authorization, CancellationToken cancellationToken = default);
}
