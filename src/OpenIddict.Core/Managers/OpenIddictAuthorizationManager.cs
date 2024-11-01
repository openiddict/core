/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using ValidationException = OpenIddict.Abstractions.OpenIddictExceptions.ValidationException;

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to manage the authorizations stored in the store.
/// </summary>
/// <remarks>
/// Applications that do not want to depend on a specific entity type can use the non-generic
/// <see cref="IOpenIddictAuthorizationManager"/> instead, for which the actual entity type
/// is resolved at runtime based on the default entity type registered in the core options.
/// </remarks>
/// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
public class OpenIddictAuthorizationManager<TAuthorization> : IOpenIddictAuthorizationManager where TAuthorization : class
{
    public OpenIddictAuthorizationManager(
        IOpenIddictAuthorizationCache<TAuthorization> cache,
        ILogger<OpenIddictAuthorizationManager<TAuthorization>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictAuthorizationStoreResolver resolver)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        Store = (resolver ?? throw new ArgumentNullException(nameof(resolver))).Get<TAuthorization>();
    }

    /// <summary>
    /// Gets the cache associated with the current manager.
    /// </summary>
    protected IOpenIddictAuthorizationCache<TAuthorization> Cache { get; }

    /// <summary>
    /// Gets the logger associated with the current manager.
    /// </summary>
    protected ILogger Logger { get; }

    /// <summary>
    /// Gets the options associated with the current manager.
    /// </summary>
    protected IOptionsMonitor<OpenIddictCoreOptions> Options { get; }

    /// <summary>
    /// Gets the store associated with the current manager.
    /// </summary>
    protected IOpenIddictAuthorizationStore<TAuthorization> Store { get; }

    /// <summary>
    /// Determines the number of authorizations that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of authorizations in the database.
    /// </returns>
    public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
        => Store.CountAsync(cancellationToken);

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
    public virtual ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.CountAsync(query, cancellationToken);
    }

    /// <summary>
    /// Creates a new authorization.
    /// </summary>
    /// <param name="authorization">The application to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask CreateAsync(TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        // If no status was explicitly specified, assume that the authorization is valid.
        if (string.IsNullOrEmpty(await Store.GetStatusAsync(authorization, cancellationToken)))
        {
            await Store.SetStatusAsync(authorization, Statuses.Valid, cancellationToken);
        }

        var results = await GetValidationResultsAsync(authorization, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0219));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.CreateAsync(authorization, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(authorization, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TAuthorization authorization, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(authorization, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Creates a new authorization based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The authorization descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the authorization.
    /// </returns>
    public virtual async ValueTask<TAuthorization> CreateAsync(
        OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        var authorization = await Store.InstantiateAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0220));

        await PopulateAsync(authorization, descriptor, cancellationToken);
        await CreateAsync(authorization, cancellationToken);

        return authorization;
    }

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
    public virtual ValueTask<TAuthorization> CreateAsync(
        ClaimsIdentity identity, string subject, string client,
        string type, ImmutableArray<string> scopes, CancellationToken cancellationToken = default)
        => CreateAsync(new ClaimsPrincipal(identity ?? throw new ArgumentNullException(nameof(identity))),
            subject, client, type, scopes, cancellationToken);

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
    public virtual ValueTask<TAuthorization> CreateAsync(
        ClaimsPrincipal principal, string subject, string client,
        string type, ImmutableArray<string> scopes, CancellationToken cancellationToken = default)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
        }

        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = client,
            CreationDate =
#if SUPPORTS_TIME_PROVIDER
                Options.CurrentValue.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow,
            Principal = principal,
            Status = Statuses.Valid,
            Subject = subject,
            Type = type
        };

        descriptor.Scopes.UnionWith(scopes);

        return CreateAsync(descriptor, cancellationToken);
    }

    /// <summary>
    /// Removes an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask DeleteAsync(TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(authorization, cancellationToken);
        }

        await Store.DeleteAsync(authorization, cancellationToken);
    }

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
    public virtual IAsyncEnumerable<TAuthorization> FindAsync(
        string? subject, string? client,
        string? status, string? type,
        ImmutableArray<string>? scopes, CancellationToken cancellationToken = default)
    {
        var authorizations = Options.CurrentValue.DisableEntityCaching ?
            Store.FindAsync(subject, client, status, type, scopes, cancellationToken) :
            Cache.FindAsync(subject, client, status, type, scopes, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return authorizations;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var authorization in authorizations)
            {
                if (!string.IsNullOrEmpty(subject) &&
                    !string.Equals(await Store.GetSubjectAsync(authorization, cancellationToken), subject, StringComparison.Ordinal))
                {
                    continue;
                }

                if (scopes is not null && !await HasScopesAsync(authorization, scopes.Value, cancellationToken))
                {
                    continue;
                }

                yield return authorization;
            }
        }
    }

    /// <summary>
    /// Retrieves the list of authorizations corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified application.</returns>
    public virtual IAsyncEnumerable<TAuthorization> FindByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var authorizations = Options.CurrentValue.DisableEntityCaching ?
            Store.FindByApplicationIdAsync(identifier, cancellationToken) :
            Cache.FindByApplicationIdAsync(identifier, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return authorizations;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var authorization in authorizations)
            {
                if (string.Equals(await Store.GetApplicationIdAsync(authorization, cancellationToken), identifier, StringComparison.Ordinal))
                {
                    yield return authorization;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves an authorization using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization corresponding to the identifier.
    /// </returns>
    public virtual async ValueTask<TAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var authorization = Options.CurrentValue.DisableEntityCaching ?
            await Store.FindByIdAsync(identifier, cancellationToken) :
            await Cache.FindByIdAsync(identifier, cancellationToken);

        if (authorization is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetIdAsync(authorization, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return authorization;
    }

    /// <summary>
    /// Retrieves all the authorizations corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified subject.</returns>
    public virtual IAsyncEnumerable<TAuthorization> FindBySubjectAsync(
        string subject, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        var authorizations = Options.CurrentValue.DisableEntityCaching ?
            Store.FindBySubjectAsync(subject, cancellationToken) :
            Cache.FindBySubjectAsync(subject, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return authorizations;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var authorization in authorizations)
            {
                if (string.Equals(await Store.GetSubjectAsync(authorization, cancellationToken), subject, StringComparison.Ordinal))
                {
                    yield return authorization;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the optional application identifier associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the authorization.
    /// </returns>
    public virtual ValueTask<string?> GetApplicationIdAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetApplicationIdAsync(authorization, cancellationToken);
    }

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
    public virtual ValueTask<TResult?> GetAsync<TResult>(
        Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return GetAsync(static (authorizations, query) => query(authorizations), query, cancellationToken);
    }

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
    public virtual ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.GetAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Retrieves the creation date associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified authorization.
    /// </returns>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetCreationDateAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Retrieves the unique identifier associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the authorization.
    /// </returns>
    public virtual ValueTask<string?> GetIdAsync(TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetIdAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Retrieves the additional properties associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the authorization.
    /// </returns>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetPropertiesAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Retrieves the scopes associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the scopes associated with the specified authorization.
    /// </returns>
    public virtual ValueTask<ImmutableArray<string>> GetScopesAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetScopesAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Retrieves the status associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified authorization.
    /// </returns>
    public virtual ValueTask<string?> GetStatusAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetStatusAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Retrieves the subject associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified authorization.
    /// </returns>
    public virtual ValueTask<string?> GetSubjectAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetSubjectAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Retrieves the type associated with an authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the type associated with the specified authorization.
    /// </returns>
    public virtual ValueTask<string?> GetTypeAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return Store.GetTypeAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Determines whether the specified scopes are included in the authorization.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="scopes">The scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the scopes are included in the authorization, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasScopesAsync(TAuthorization authorization,
        ImmutableArray<string> scopes, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return (await Store.GetScopesAsync(authorization, cancellationToken))
            .ToHashSet(StringComparer.Ordinal)
            .IsSupersetOf(scopes);
    }

    /// <summary>
    /// Determines whether a given authorization has the specified status.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="status">The expected status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authorization has the specified status, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasStatusAsync(TAuthorization authorization,
        string status, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        return string.Equals(await Store.GetStatusAsync(authorization, cancellationToken), status, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether a given authorization has the specified type.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="type">The expected type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authorization has the specified type, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasTypeAsync(
        TAuthorization authorization, string type, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
        }

        return string.Equals(await Store.GetTypeAsync(authorization, cancellationToken), type, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TAuthorization> ListAsync(
        int? count = null, int? offset = null, CancellationToken cancellationToken = default)
        => Store.ListAsync(count, offset, cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResult> ListAsync<TResult>(
        Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return ListAsync(static (authorizations, query) => query(authorizations), query, cancellationToken);
    }

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.ListAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Populates the authorization using the specified descriptor.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(TAuthorization authorization,
        OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        await Store.SetApplicationIdAsync(authorization, descriptor.ApplicationId, cancellationToken);
        await Store.SetCreationDateAsync(authorization, descriptor.CreationDate, cancellationToken);
        await Store.SetPropertiesAsync(authorization, descriptor.Properties.ToImmutableDictionary(), cancellationToken);
        await Store.SetScopesAsync(authorization, descriptor.Scopes.ToImmutableArray(), cancellationToken);
        await Store.SetStatusAsync(authorization, descriptor.Status, cancellationToken);
        await Store.SetSubjectAsync(authorization, descriptor.Subject, cancellationToken);
        await Store.SetTypeAsync(authorization, descriptor.Type, cancellationToken);
    }

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the authorization.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(
        OpenIddictAuthorizationDescriptor descriptor,
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        descriptor.ApplicationId = await Store.GetApplicationIdAsync(authorization, cancellationToken);
        descriptor.CreationDate = await Store.GetCreationDateAsync(authorization, cancellationToken);
        descriptor.Scopes.Clear();
        descriptor.Scopes.UnionWith(await Store.GetScopesAsync(authorization, cancellationToken));
        descriptor.Status = await Store.GetStatusAsync(authorization, cancellationToken);
        descriptor.Subject = await Store.GetSubjectAsync(authorization, cancellationToken);
        descriptor.Type = await Store.GetTypeAsync(authorization, cancellationToken);

        descriptor.Properties.Clear();
        foreach (var pair in await Store.GetPropertiesAsync(authorization, cancellationToken))
        {
            descriptor.Properties.Add(pair.Key, pair.Value);
        }
    }

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
    public virtual ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default)
        => Store.PruneAsync(threshold, cancellationToken);

    /// <summary>
    /// Revokes all the authorizations matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization, or <see langword="null"/> not to filter out specific subjects.</param>
    /// <param name="client">The client associated with the authorization, or <see langword="null"/> not to filter out specific clients.</param>
    /// <param name="status">The authorization status, or <see langword="null"/> not to filter out specific authorization statuses.</param>
    /// <param name="type">The authorization type, or <see langword="null"/> not to filter out specific authorization types.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations corresponding to the criteria that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken = default)
        => Store.RevokeAsync(subject, client, status, type, cancellationToken);

    /// <summary>
    /// Revokes all the authorizations associated with the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations associated with the specified application that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        return Store.RevokeByApplicationIdAsync(identifier, cancellationToken);
    }

    /// <summary>
    /// Revokes all the authorizations associated with the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of authorizations associated with the specified subject that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(subject));
        }

        return Store.RevokeBySubjectAsync(subject, cancellationToken);
    }

    /// <summary>
    /// Tries to revoke an authorization.
    /// </summary>
    /// <param name="authorization">The authorization to revoke.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authorization was successfully revoked, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> TryRevokeAsync(TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var status = await Store.GetStatusAsync(authorization, cancellationToken);
        if (string.Equals(status, Statuses.Revoked, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        await Store.SetStatusAsync(authorization, Statuses.Revoked, cancellationToken);

        try
        {
            await UpdateAsync(authorization, cancellationToken);

            Logger.LogInformation(SR.GetResourceString(SR.ID6164), await Store.GetIdAsync(authorization, cancellationToken));

            return true;
        }

        catch (ConcurrencyException exception)
        {
            Logger.LogDebug(exception, SR.GetResourceString(SR.ID6165), await Store.GetIdAsync(authorization, cancellationToken));

            return false;
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            Logger.LogWarning(exception, SR.GetResourceString(SR.ID6166), await Store.GetIdAsync(authorization, cancellationToken));

            return false;
        }
    }

    /// <summary>
    /// Updates an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var results = await GetValidationResultsAsync(authorization, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0221));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.UpdateAsync(authorization, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(authorization, cancellationToken);
            await Cache.AddAsync(authorization, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TAuthorization authorization, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(authorization, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Updates an existing authorization.
    /// </summary>
    /// <param name="authorization">The authorization to update.</param>
    /// <param name="descriptor">The descriptor used to update the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TAuthorization authorization,
        OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        await PopulateAsync(authorization, descriptor, cancellationToken);
        await UpdateAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// Validates the authorization to ensure it's in a consistent state.
    /// </summary>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the authorization.</returns>
    public virtual IAsyncEnumerable<ValidationResult> ValidateAsync(
        TAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<ValidationResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var type = await Store.GetTypeAsync(authorization, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2116));
            }

            else if (!string.Equals(type, AuthorizationTypes.AdHoc, StringComparison.OrdinalIgnoreCase) &&
                     !string.Equals(type, AuthorizationTypes.Permanent, StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2117));
            }

            if (string.IsNullOrEmpty(await Store.GetStatusAsync(authorization, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2038));
            }

            // Ensure that the scopes are not null or empty and do not contain spaces.
            foreach (var scope in await Store.GetScopesAsync(authorization, cancellationToken))
            {
                if (string.IsNullOrEmpty(scope))
                {
                    yield return new ValidationResult(SR.GetResourceString(SR.ID2039));

                    break;
                }

                if (scope.Contains(Separators.Space[0]))
                {
                    yield return new ValidationResult(SR.GetResourceString(SR.ID2042));

                    break;
                }
            }
        }
    }

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictAuthorizationManager.CountAsync(CancellationToken cancellationToken)
        => CountAsync(cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictAuthorizationManager.CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => CountAsync(query, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictAuthorizationManager.CreateAsync(ClaimsIdentity identity, string subject, string client, string type, ImmutableArray<string> scopes, CancellationToken cancellationToken)
        => await CreateAsync(identity, subject, client, type, scopes, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictAuthorizationManager.CreateAsync(ClaimsPrincipal principal, string subject, string client, string type, ImmutableArray<string> scopes, CancellationToken cancellationToken)
        => await CreateAsync(principal, subject, client, type, scopes, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictAuthorizationManager.CreateAsync(OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken)
        => await CreateAsync(descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictAuthorizationManager.CreateAsync(object authorization, CancellationToken cancellationToken)
        => CreateAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictAuthorizationManager.DeleteAsync(object authorization, CancellationToken cancellationToken)
        => DeleteAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictAuthorizationManager.FindAsync(string? subject, string? client, string? status, string? type, ImmutableArray<string>? scopes, CancellationToken cancellationToken)
        => FindAsync(subject, client, status, type, scopes, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictAuthorizationManager.FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByApplicationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictAuthorizationManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictAuthorizationManager.FindBySubjectAsync(string subject, CancellationToken cancellationToken)
        => FindBySubjectAsync(subject, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictAuthorizationManager.GetApplicationIdAsync(object authorization, CancellationToken cancellationToken)
        => GetApplicationIdAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictAuthorizationManager.GetAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictAuthorizationManager.GetAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, state, cancellationToken);

    ValueTask<DateTimeOffset?> IOpenIddictAuthorizationManager.GetCreationDateAsync(object authorization, CancellationToken cancellationToken)
        => GetCreationDateAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictAuthorizationManager.GetIdAsync(object authorization, CancellationToken cancellationToken)
        => GetIdAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<string, JsonElement>> IOpenIddictAuthorizationManager.GetPropertiesAsync(object authorization, CancellationToken cancellationToken)
        => GetPropertiesAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableArray<string>> IOpenIddictAuthorizationManager.GetScopesAsync(object authorization, CancellationToken cancellationToken)
        => GetScopesAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictAuthorizationManager.GetStatusAsync(object authorization, CancellationToken cancellationToken)
        => GetStatusAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictAuthorizationManager.GetSubjectAsync(object authorization, CancellationToken cancellationToken)
        => GetSubjectAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictAuthorizationManager.GetTypeAsync(object authorization, CancellationToken cancellationToken)
        => GetTypeAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictAuthorizationManager.HasScopesAsync(object authorization, ImmutableArray<string> scopes, CancellationToken cancellationToken)
        => HasScopesAsync((TAuthorization) authorization, scopes, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictAuthorizationManager.HasStatusAsync(object authorization, string status, CancellationToken cancellationToken)
        => HasStatusAsync((TAuthorization) authorization, status, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictAuthorizationManager.HasTypeAsync(object authorization, string type, CancellationToken cancellationToken)
        => HasTypeAsync((TAuthorization) authorization, type, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictAuthorizationManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => ListAsync(count, offset, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictAuthorizationManager.ListAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => ListAsync(query, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictAuthorizationManager.ListAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => ListAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictAuthorizationManager.PopulateAsync(OpenIddictAuthorizationDescriptor descriptor, object authorization, CancellationToken cancellationToken)
        => PopulateAsync(descriptor, (TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictAuthorizationManager.PopulateAsync(object authorization, OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken)
        => PopulateAsync((TAuthorization) authorization, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictAuthorizationManager.PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
        => PruneAsync(threshold, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictAuthorizationManager.RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken)
        => RevokeAsync(subject, client, status, type, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictAuthorizationManager.RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        => RevokeByApplicationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictAuthorizationManager.RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
        => RevokeBySubjectAsync(subject, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictAuthorizationManager.TryRevokeAsync(object authorization, CancellationToken cancellationToken)
        => TryRevokeAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictAuthorizationManager.UpdateAsync(object authorization, CancellationToken cancellationToken)
        => UpdateAsync((TAuthorization) authorization, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictAuthorizationManager.UpdateAsync(object authorization, OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken)
        => UpdateAsync((TAuthorization) authorization, descriptor, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<ValidationResult> IOpenIddictAuthorizationManager.ValidateAsync(object authorization, CancellationToken cancellationToken)
        => ValidateAsync((TAuthorization) authorization, cancellationToken);
}
