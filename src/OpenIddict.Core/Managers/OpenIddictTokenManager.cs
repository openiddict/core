/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using ValidationException = OpenIddict.Abstractions.OpenIddictExceptions.ValidationException;

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to manage the tokens stored in the store.
/// </summary>
/// <remarks>
/// Applications that do not want to depend on a specific entity type can use the non-generic
/// <see cref="IOpenIddictTokenManager"/> instead, for which the actual entity type
/// is resolved at runtime based on the default entity type registered in the core options.
/// </remarks>
/// <typeparam name="TToken">The type of the Token entity.</typeparam>
public class OpenIddictTokenManager<TToken> : IOpenIddictTokenManager where TToken : class
{
    public OpenIddictTokenManager(
        IOpenIddictTokenCache<TToken> cache,
        ILogger<OpenIddictTokenManager<TToken>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictTokenStoreResolver resolver)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        Store = (resolver ?? throw new ArgumentNullException(nameof(resolver))).Get<TToken>();
    }

    /// <summary>
    /// Gets the cache associated with the current manager.
    /// </summary>
    protected IOpenIddictTokenCache<TToken> Cache { get; }

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
    protected IOpenIddictTokenStore<TToken> Store { get; }

    /// <summary>
    /// Determines the number of tokens that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of tokens in the database.
    /// </returns>
    public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
        => Store.CountAsync(cancellationToken);

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
    public virtual ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.CountAsync(query, cancellationToken);
    }

    /// <summary>
    /// Creates a new token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask CreateAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        // If no status was explicitly specified, assume that the token is valid.
        if (string.IsNullOrEmpty(await Store.GetStatusAsync(token, cancellationToken)))
        {
            await Store.SetStatusAsync(token, Statuses.Valid, cancellationToken);
        }

        // If a reference identifier was set, obfuscate it.
        var identifier = await Store.GetReferenceIdAsync(token, cancellationToken);
        if (!string.IsNullOrEmpty(identifier))
        {
            identifier = await ObfuscateReferenceIdAsync(identifier, cancellationToken);
            await Store.SetReferenceIdAsync(token, identifier, cancellationToken);
        }

        var results = await GetValidationResultsAsync(token, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0225));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.CreateAsync(token, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(token, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TToken token, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(token, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Creates a new token based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The token descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the token.
    /// </returns>
    public virtual async ValueTask<TToken> CreateAsync(
        OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        var token = await Store.InstantiateAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0226));

        await PopulateAsync(token, descriptor, cancellationToken);
        await CreateAsync(token, cancellationToken);

        return token;
    }

    /// <summary>
    /// Removes an existing token.
    /// </summary>
    /// <param name="token">The token to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask DeleteAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(token, cancellationToken);
        }

        await Store.DeleteAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the tokens corresponding to the specified
    /// subject and associated with the application identifier.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the subject/client.</returns>
    public virtual IAsyncEnumerable<TToken> FindAsync(string subject,
        string client, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        var tokens = Options.CurrentValue.DisableEntityCaching ?
            Store.FindAsync(subject, client, cancellationToken) :
            Cache.FindAsync(subject, client, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return tokens;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var token in tokens)
            {
                if (string.Equals(await Store.GetSubjectAsync(token, cancellationToken), subject, StringComparison.Ordinal))
                {
                    yield return token;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the criteria.</returns>
    public virtual IAsyncEnumerable<TToken> FindAsync(
        string subject, string client,
        string status, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        var tokens = Options.CurrentValue.DisableEntityCaching ?
            Store.FindAsync(subject, client, status, cancellationToken) :
            Cache.FindAsync(subject, client, status, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return tokens;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var token in tokens)
            {
                if (string.Equals(await Store.GetSubjectAsync(token, cancellationToken), subject, StringComparison.Ordinal))
                {
                    yield return token;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="type">The token type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>Tokens corresponding to the criteria.</returns>
    public virtual IAsyncEnumerable<TToken> FindAsync(
        string subject, string client,
        string status, string type, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
        }

        var tokens = Options.CurrentValue.DisableEntityCaching ?
            Store.FindAsync(subject, client, status, type, cancellationToken) :
            Cache.FindAsync(subject, client, status, type, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return tokens;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var token in tokens)
            {
                if (string.Equals(await Store.GetSubjectAsync(token, cancellationToken), subject, StringComparison.Ordinal))
                {
                    yield return token;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified application.</returns>
    public virtual IAsyncEnumerable<TToken> FindByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var tokens = Options.CurrentValue.DisableEntityCaching ?
            Store.FindByApplicationIdAsync(identifier, cancellationToken) :
            Cache.FindByApplicationIdAsync(identifier, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return tokens;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var token in tokens)
            {
                if (string.Equals(await Store.GetApplicationIdAsync(token, cancellationToken), identifier, StringComparison.Ordinal))
                {
                    yield return token;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified authorization.</returns>
    public virtual IAsyncEnumerable<TToken> FindByAuthorizationIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var tokens = Options.CurrentValue.DisableEntityCaching ?
            Store.FindByAuthorizationIdAsync(identifier, cancellationToken) :
            Cache.FindByAuthorizationIdAsync(identifier, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return tokens;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var token in tokens)
            {
                if (string.Equals(await Store.GetAuthorizationIdAsync(token, cancellationToken), identifier, StringComparison.Ordinal))
                {
                    yield return token;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves a token using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the token corresponding to the unique identifier.
    /// </returns>
    public virtual async ValueTask<TToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var token = Options.CurrentValue.DisableEntityCaching ?
            await Store.FindByIdAsync(identifier, cancellationToken) :
            await Cache.FindByIdAsync(identifier, cancellationToken);

        if (token is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetIdAsync(token, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return token;
    }

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
    public virtual async ValueTask<TToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        identifier = await ObfuscateReferenceIdAsync(identifier, cancellationToken);

        var token = Options.CurrentValue.DisableEntityCaching ?
            await Store.FindByReferenceIdAsync(identifier, cancellationToken) :
            await Cache.FindByReferenceIdAsync(identifier, cancellationToken);

        if (token is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetReferenceIdAsync(token, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return token;
    }

    /// <summary>
    /// Retrieves the list of tokens corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens corresponding to the specified subject.</returns>
    public virtual IAsyncEnumerable<TToken> FindBySubjectAsync(
        string subject, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        var tokens = Options.CurrentValue.DisableEntityCaching ?
            Store.FindBySubjectAsync(subject, cancellationToken) :
            Cache.FindBySubjectAsync(subject, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return tokens;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var token in tokens)
            {
                if (string.Equals(await Store.GetSubjectAsync(token, cancellationToken), subject, StringComparison.Ordinal))
                {
                    yield return token;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the optional application identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the token.
    /// </returns>
    public virtual ValueTask<string?> GetApplicationIdAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetApplicationIdAsync(token, cancellationToken);
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
        Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return GetAsync(static (tokens, query) => query(tokens), query, cancellationToken);
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
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.GetAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Retrieves the optional authorization identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization identifier associated with the token.
    /// </returns>
    public virtual ValueTask<string?> GetAuthorizationIdAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetAuthorizationIdAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the creation date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified token.
    /// </returns>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetCreationDateAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the expiration date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the expiration date associated with the specified token.
    /// </returns>
    public virtual ValueTask<DateTimeOffset?> GetExpirationDateAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetExpirationDateAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the unique identifier associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the token.
    /// </returns>
    public virtual ValueTask<string?> GetIdAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetIdAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the payload associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the payload associated with the specified token.
    /// </returns>
    public virtual ValueTask<string?> GetPayloadAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetPayloadAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the additional properties associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the token.
    /// </returns>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetPropertiesAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the redemption date associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the redemption date associated with the specified token.
    /// </returns>
    public virtual ValueTask<DateTimeOffset?> GetRedemptionDateAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetRedemptionDateAsync(token, cancellationToken);
    }

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
    public virtual ValueTask<string?> GetReferenceIdAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetReferenceIdAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the status associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified token.
    /// </returns>
    public virtual ValueTask<string?> GetStatusAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetStatusAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the subject associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified token.
    /// </returns>
    public virtual ValueTask<string?> GetSubjectAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetSubjectAsync(token, cancellationToken);
    }

    /// <summary>
    /// Retrieves the token type associated with a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the token type associated with the specified token.
    /// </returns>
    public virtual ValueTask<string?> GetTypeAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return Store.GetTypeAsync(token, cancellationToken);
    }

    /// <summary>
    /// Determines whether a given token has the specified status.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="status">The expected status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token has the specified status, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasStatusAsync(TToken token, string status, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        return string.Equals(await Store.GetStatusAsync(token, cancellationToken), status, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether a given token has the specified type.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="type">The expected type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token has the specified type, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasTypeAsync(TToken token, string type, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
        }

        return string.Equals(await Store.GetTypeAsync(token, cancellationToken), type, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether a given token has any of the specified types.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="types">The expected types.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token has any of the specified types, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasTypeAsync(TToken token, ImmutableArray<string> types, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        var type = await Store.GetTypeAsync(token, cancellationToken);
        if (string.IsNullOrEmpty(type))
        {
            return false;
        }

        for (var index = 0; index < types.Length; index++)
        {
            if (string.Equals(type, types[index], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TToken> ListAsync(
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
        Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return ListAsync(static (tokens, query) => query(tokens), query, cancellationToken);
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
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.ListAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Populates the token using the specified descriptor.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(TToken token,
        OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        await Store.SetApplicationIdAsync(token, descriptor.ApplicationId, cancellationToken);
        await Store.SetAuthorizationIdAsync(token, descriptor.AuthorizationId, cancellationToken);
        await Store.SetCreationDateAsync(token, descriptor.CreationDate, cancellationToken);
        await Store.SetExpirationDateAsync(token, descriptor.ExpirationDate, cancellationToken);
        await Store.SetPayloadAsync(token, descriptor.Payload, cancellationToken);
        await Store.SetPropertiesAsync(token, descriptor.Properties.ToImmutableDictionary(), cancellationToken);
        await Store.SetRedemptionDateAsync(token, descriptor.RedemptionDate, cancellationToken);
        await Store.SetReferenceIdAsync(token, descriptor.ReferenceId, cancellationToken);
        await Store.SetStatusAsync(token, descriptor.Status, cancellationToken);
        await Store.SetSubjectAsync(token, descriptor.Subject, cancellationToken);
        await Store.SetTypeAsync(token, descriptor.Type, cancellationToken);
    }

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the token.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(
        OpenIddictTokenDescriptor descriptor,
        TToken token, CancellationToken cancellationToken = default)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        descriptor.ApplicationId = await Store.GetApplicationIdAsync(token, cancellationToken);
        descriptor.AuthorizationId = await Store.GetAuthorizationIdAsync(token, cancellationToken);
        descriptor.CreationDate = await Store.GetCreationDateAsync(token, cancellationToken);
        descriptor.ExpirationDate = await Store.GetExpirationDateAsync(token, cancellationToken);
        descriptor.Payload = await Store.GetPayloadAsync(token, cancellationToken);
        descriptor.RedemptionDate = await Store.GetRedemptionDateAsync(token, cancellationToken);
        descriptor.ReferenceId = await Store.GetReferenceIdAsync(token, cancellationToken);
        descriptor.Status = await Store.GetStatusAsync(token, cancellationToken);
        descriptor.Subject = await Store.GetSubjectAsync(token, cancellationToken);
        descriptor.Type = await Store.GetTypeAsync(token, cancellationToken);

        descriptor.Properties.Clear();
        foreach (var pair in await Store.GetPropertiesAsync(token, cancellationToken))
        {
            descriptor.Properties.Add(pair.Key, pair.Value);
        }
    }

    /// <summary>
    /// Removes the tokens that are marked as invalid or whose attached authorization is no longer valid.
    /// Only tokens created before the specified <paramref name="threshold"/> are removed.
    /// </summary>
    /// <param name="threshold">The date before which tokens are not pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens that were removed.</returns>
    public virtual ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default)
        => Store.PruneAsync(threshold, cancellationToken);

    /// <summary>
    /// Revokes all the tokens corresponding to the specified
    /// subject and associated with the application identifier.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens corresponding to the criteria that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeAsync(string subject, string client, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        return Store.RevokeAsync(subject, client, cancellationToken);
    }

    /// <summary>
    /// Revokes all the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens corresponding to the criteria that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeAsync(string subject, string client, string status, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        return Store.RevokeAsync(subject, client, status, cancellationToken);
    }

    /// <summary>
    /// Revokes all the tokens matching the specified parameters.
    /// </summary>
    /// <param name="subject">The subject associated with the token.</param>
    /// <param name="client">The client associated with the token.</param>
    /// <param name="status">The token status.</param>
    /// <param name="type">The token type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens corresponding to the criteria that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeAsync(string subject, string client, string status, string type, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
        }

        return Store.RevokeAsync(subject, client, status, type, cancellationToken);
    }

    /// <summary>
    /// Revokes all the tokens associated with the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens associated with the specified application that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        return Store.RevokeByApplicationIdAsync(identifier, cancellationToken);
    }

    /// <summary>
    /// Revokes all the tokens associated with the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens associated with the specified authorization that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        return Store.RevokeByAuthorizationIdAsync(identifier, cancellationToken);
    }

    /// <summary>
    /// Revokes all the tokens associated with the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the tokens.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of tokens associated with the specified subject that were marked as revoked.</returns>
    public virtual ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(subject));
        }

        return Store.RevokeBySubjectAsync(subject, cancellationToken);
    }

    /// <summary>
    /// Tries to redeem a token.
    /// </summary>
    /// <param name="token">The token to redeem.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token was successfully redemeed, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> TryRedeemAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        // If the token doesn't have a redemption date attached, this likely means it's
        // the first time the token is redeemed. In this case, attach the current date.
        if (await Store.GetRedemptionDateAsync(token, cancellationToken) is null)
        {
            await Store.SetRedemptionDateAsync(token,
#if SUPPORTS_TIME_PROVIDER
                Options.CurrentValue.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow, cancellationToken);
        }

        await Store.SetStatusAsync(token, Statuses.Redeemed, cancellationToken);

        try
        {
            await UpdateAsync(token, cancellationToken);

            Logger.LogInformation(SR.GetResourceString(SR.ID6168), await Store.GetIdAsync(token, cancellationToken));

            return true;
        }

        catch (ConcurrencyException exception)
        {
            Logger.LogDebug(exception, SR.GetResourceString(SR.ID6169), await Store.GetIdAsync(token, cancellationToken));

            return false;
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            Logger.LogWarning(exception, SR.GetResourceString(SR.ID6170), await Store.GetIdAsync(token, cancellationToken));

            return false;
        }
    }

    /// <summary>
    /// Tries to reject a token.
    /// </summary>
    /// <param name="token">The token to reject.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token was successfully redemeed, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> TryRejectAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        await Store.SetStatusAsync(token, Statuses.Rejected, cancellationToken);

        try
        {
            await UpdateAsync(token, cancellationToken);

            Logger.LogInformation(SR.GetResourceString(SR.ID6171), await Store.GetIdAsync(token, cancellationToken));

            return true;
        }

        catch (ConcurrencyException exception)
        {
            Logger.LogDebug(exception, SR.GetResourceString(SR.ID6172), await Store.GetIdAsync(token, cancellationToken));

            return false;
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            Logger.LogWarning(exception, SR.GetResourceString(SR.ID6173), await Store.GetIdAsync(token, cancellationToken));

            return false;
        }
    }

    /// <summary>
    /// Tries to revoke a token.
    /// </summary>
    /// <param name="token">The token to revoke.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the token was successfully revoked, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> TryRevokeAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        await Store.SetStatusAsync(token, Statuses.Revoked, cancellationToken);

        try
        {
            await UpdateAsync(token, cancellationToken);

            Logger.LogInformation(SR.GetResourceString(SR.ID6174), await Store.GetIdAsync(token, cancellationToken));

            return true;
        }

        catch (ConcurrencyException exception)
        {
            Logger.LogDebug(exception, SR.GetResourceString(SR.ID6175), await Store.GetIdAsync(token, cancellationToken));

            return false;
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            Logger.LogWarning(exception, SR.GetResourceString(SR.ID6176), await Store.GetIdAsync(token, cancellationToken));

            return false;
        }
    }

    /// <summary>
    /// Updates an existing token.
    /// </summary>
    /// <param name="token">The token to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        var results = await GetValidationResultsAsync(token, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0227));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.UpdateAsync(token, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(token, cancellationToken);
            await Cache.AddAsync(token, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TToken token, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(token, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Updates an existing token.
    /// </summary>
    /// <param name="token">The token to update.</param>
    /// <param name="descriptor">The descriptor used to update the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TToken token,
        OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        // Store the original reference identifier for later comparison.
        var comparand = await Store.GetReferenceIdAsync(token, cancellationToken);
        await PopulateAsync(token, descriptor, cancellationToken);

        // If the reference identifier was updated, re-obfuscate it before persisting the changes.
        var identifier = await Store.GetReferenceIdAsync(token, cancellationToken);
        if (!string.IsNullOrEmpty(identifier) && !string.Equals(identifier, comparand, StringComparison.Ordinal))
        {
            identifier = await ObfuscateReferenceIdAsync(identifier, cancellationToken);
            await Store.SetReferenceIdAsync(token, identifier, cancellationToken);
        }

        await UpdateAsync(token, cancellationToken);
    }

    /// <summary>
    /// Validates the token to ensure it's in a consistent state.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the token.</returns>
    public virtual IAsyncEnumerable<ValidationResult> ValidateAsync(TToken token, CancellationToken cancellationToken = default)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<ValidationResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            // If a reference identifier was associated with the token,
            // ensure it's not already used for a different token.
            var identifier = await Store.GetReferenceIdAsync(token, cancellationToken);
            if (!string.IsNullOrEmpty(identifier))
            {
                // Note: depending on the database/table/query collation used by the store, a reference token
                // whose identifier doesn't exactly match the specified value may be returned (e.g because
                // the casing is different). To avoid issues when the reference identifier is part of an index
                // using the same collation, an error is added even if the two identifiers don't exactly match.
                var other = await Store.FindByReferenceIdAsync(identifier, cancellationToken);
                if (other is not null && !string.Equals(
                    await Store.GetIdAsync(other, cancellationToken),
                    await Store.GetIdAsync(token, cancellationToken), StringComparison.Ordinal))
                {
                    yield return new ValidationResult(SR.GetResourceString(SR.ID2085));
                }
            }

            var type = await Store.GetTypeAsync(token, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2086));
            }

            if (string.IsNullOrEmpty(await Store.GetStatusAsync(token, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2038));
            }
        }
    }

    /// <summary>
    /// Obfuscates the specified reference identifier so it can be safely stored in a database.
    /// By default, this method returns a simple hashed representation computed using SHA256.
    /// </summary>
    /// <param name="identifier">The client identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    protected virtual ValueTask<string> ObfuscateReferenceIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        // Compute the digest of the generated identifier and use it as the hashed identifier of the reference token.
        // Doing that prevents token identifiers stolen from the database from being used as valid reference tokens.
        return new(Convert.ToBase64String(OpenIddictHelpers.ComputeSha256Hash(Encoding.UTF8.GetBytes(identifier))));
    }

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.CountAsync(CancellationToken cancellationToken)
        => CountAsync(cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => CountAsync(query, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictTokenManager.CreateAsync(OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken)
        => await CreateAsync(descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictTokenManager.CreateAsync(object token, CancellationToken cancellationToken)
        => CreateAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictTokenManager.DeleteAsync(object token, CancellationToken cancellationToken)
        => DeleteAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictTokenManager.FindAsync(string subject, string client, CancellationToken cancellationToken)
        => FindAsync(subject, client, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictTokenManager.FindAsync(string subject, string client, string status, CancellationToken cancellationToken)
        => FindAsync(subject, client, status, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictTokenManager.FindAsync(string subject, string client, string status, string type, CancellationToken cancellationToken)
        => FindAsync(subject, client, status, type, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictTokenManager.FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByApplicationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictTokenManager.FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByAuthorizationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictTokenManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictTokenManager.FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByReferenceIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictTokenManager.FindBySubjectAsync(string subject, CancellationToken cancellationToken)
        => FindBySubjectAsync(subject, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetApplicationIdAsync(object token, CancellationToken cancellationToken)
        => GetApplicationIdAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictTokenManager.GetAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictTokenManager.GetAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetAuthorizationIdAsync(object token, CancellationToken cancellationToken)
        => GetAuthorizationIdAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictTokenManager.GetCreationDateAsync(object token, CancellationToken cancellationToken)
        => GetCreationDateAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictTokenManager.GetExpirationDateAsync(object token, CancellationToken cancellationToken)
        => GetExpirationDateAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetIdAsync(object token, CancellationToken cancellationToken)
        => GetIdAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetPayloadAsync(object token, CancellationToken cancellationToken)
        => GetPayloadAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<string, JsonElement>> IOpenIddictTokenManager.GetPropertiesAsync(object token, CancellationToken cancellationToken)
        => GetPropertiesAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictTokenManager.GetRedemptionDateAsync(object token, CancellationToken cancellationToken)
        => GetRedemptionDateAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetReferenceIdAsync(object token, CancellationToken cancellationToken)
        => GetReferenceIdAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetStatusAsync(object token, CancellationToken cancellationToken)
        => GetStatusAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetSubjectAsync(object token, CancellationToken cancellationToken)
        => GetSubjectAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictTokenManager.GetTypeAsync(object token, CancellationToken cancellationToken)
        => GetTypeAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictTokenManager.HasStatusAsync(object token, string status, CancellationToken cancellationToken)
        => HasStatusAsync((TToken) token, status, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictTokenManager.HasTypeAsync(object token, string type, CancellationToken cancellationToken)
        => HasTypeAsync((TToken) token, type, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictTokenManager.HasTypeAsync(object token, ImmutableArray<string> types, CancellationToken cancellationToken)
        => HasTypeAsync((TToken) token, types, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictTokenManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => ListAsync(count, offset, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictTokenManager.ListAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => ListAsync(query, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictTokenManager.ListAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => ListAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictTokenManager.PopulateAsync(OpenIddictTokenDescriptor descriptor, object token, CancellationToken cancellationToken)
        => PopulateAsync(descriptor, (TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictTokenManager.PopulateAsync(object token, OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken)
        => PopulateAsync((TToken) token, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
        => PruneAsync(threshold, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.RevokeAsync(string subject, string client, CancellationToken cancellationToken)
        => RevokeAsync(subject, client, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.RevokeAsync(string subject, string client, string status, CancellationToken cancellationToken)
        => RevokeAsync(subject, client, status, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.RevokeAsync(string subject, string client, string status, string type, CancellationToken cancellationToken)
        => RevokeAsync(subject, client, status, type, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        => RevokeByApplicationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
        => RevokeByAuthorizationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictTokenManager.RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
        => RevokeBySubjectAsync(subject, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictTokenManager.TryRedeemAsync(object token, CancellationToken cancellationToken)
        => TryRedeemAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictTokenManager.TryRejectAsync(object token, CancellationToken cancellationToken)
        => TryRejectAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictTokenManager.TryRevokeAsync(object token, CancellationToken cancellationToken)
        => TryRevokeAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictTokenManager.UpdateAsync(object token, CancellationToken cancellationToken)
        => UpdateAsync((TToken) token, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictTokenManager.UpdateAsync(object token, OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken)
        => UpdateAsync((TToken) token, descriptor, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<ValidationResult> IOpenIddictTokenManager.ValidateAsync(object token, CancellationToken cancellationToken)
        => ValidateAsync((TToken) token, cancellationToken);
}
