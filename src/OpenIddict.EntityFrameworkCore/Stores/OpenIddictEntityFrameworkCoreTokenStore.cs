/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Data;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
public class OpenIddictEntityFrameworkCoreTokenStore<TContext> :
    OpenIddictEntityFrameworkCoreTokenStore<OpenIddictEntityFrameworkCoreToken,
                                            OpenIddictEntityFrameworkCoreApplication,
                                            OpenIddictEntityFrameworkCoreAuthorization, TContext, string>
    where TContext : DbContext
{
    public OpenIddictEntityFrameworkCoreTokenStore(
        IMemoryCache cache,
        TContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(cache, context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreTokenStore<TContext, TKey> :
    OpenIddictEntityFrameworkCoreTokenStore<OpenIddictEntityFrameworkCoreToken<TKey>,
                                            OpenIddictEntityFrameworkCoreApplication<TKey>,
                                            OpenIddictEntityFrameworkCoreAuthorization<TKey>, TContext, TKey>
    where TContext : DbContext
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreTokenStore(
        IMemoryCache cache,
        TContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(cache, context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TToken">The type of the Token entity.</typeparam>
/// <typeparam name="TApplication">The type of the Application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
/// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreTokenStore<TToken, TApplication, TAuthorization, TContext, TKey> : IOpenIddictTokenStore<TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
    where TContext : DbContext
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreTokenStore(
        IMemoryCache cache,
        TContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Gets the memory cache associated with the current store.
    /// </summary>
    protected IMemoryCache Cache { get; }

    /// <summary>
    /// Gets the database context associated with the current store.
    /// </summary>
    protected TContext Context { get; }

    /// <summary>
    /// Gets the options associated with the current store.
    /// </summary>
    protected IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> Options { get; }

    /// <summary>
    /// Gets the database set corresponding to the <typeparamref name="TApplication"/> entity.
    /// </summary>
    private DbSet<TApplication> Applications => Context.Set<TApplication>();

    /// <summary>
    /// Gets the database set corresponding to the <typeparamref name="TAuthorization"/> entity.
    /// </summary>
    private DbSet<TAuthorization> Authorizations => Context.Set<TAuthorization>();

    /// <summary>
    /// Gets the database set corresponding to the <typeparamref name="TToken"/> entity.
    /// </summary>
    private DbSet<TToken> Tokens => Context.Set<TToken>();

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
        => await Tokens.AsQueryable().LongCountAsync(cancellationToken);

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TResult>(Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return await query(Tokens).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        Context.Add(token);

        await Context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        Context.Remove(token);

        try
        {
            await Context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            Context.Entry(token).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0247), exception);
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindAsync(
        string? subject, string? client,
        string? status, string? type, CancellationToken cancellationToken)
    {
        IQueryable<TToken> query = Tokens.Include(token => token.Application).Include(token => token.Authorization).AsTracking();

        if (!string.IsNullOrEmpty(subject))
        {
            query = query.Where(token => token.Subject == subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations
            // can't be filtered using authorization.Application.Id.Equals(key). To work around
            // this issue, this query uses use an explicit join to apply the equality check.
            //
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.
            var key = ConvertIdentifierFromString(client);

            query = from authorization in query
                    join application in Applications.AsTracking() on authorization.Application!.Id equals application.Id
                    where application.Id!.Equals(key)
                    select authorization;
        }

        if (!string.IsNullOrEmpty(status))
        {
            query = query.Where(token => token.Status == status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            query = query.Where(token => token.Type == type);
        }

        return query.AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        // Note: due to a bug in Entity Framework Core's query visitor, the tokens
        // can't be filtered using token.Application.Id.Equals(key). To work around
        // this issue, this query uses use an explicit join to apply the equality check.
        //
        // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

        var key = ConvertIdentifierFromString(identifier);

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization).AsTracking()
                join application in Applications.AsTracking() on token.Application!.Id equals application.Id
                where application.Id!.Equals(key)
                select token).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        // Note: due to a bug in Entity Framework Core's query visitor, the tokens
        // can't be filtered using token.Authorization.Id.Equals(key). To work around
        // this issue, this query uses use an explicit join to apply the equality check.
        //
        // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

        var key = ConvertIdentifierFromString(identifier);

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization).AsTracking()
                join authorization in Authorizations.AsTracking() on token.Authorization!.Id equals authorization.Id
                where authorization.Id!.Equals(key)
                select token).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var key = ConvertIdentifierFromString(identifier);

        return GetTrackedEntity() is TToken token ? new(token) : new(QueryAsync());

        TToken? GetTrackedEntity() =>
            (from entry in Context.ChangeTracker.Entries<TToken>()
             where entry.Entity.Id is TKey identifier && identifier.Equals(key)
             select entry.Entity).FirstOrDefault();

        Task<TToken?> QueryAsync() =>
            (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization).AsTracking()
             where token.Id!.Equals(key)
             select token).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        return GetTrackedEntity() is TToken token ? new(token) : new(QueryAsync());

        TToken? GetTrackedEntity() =>
            (from entry in Context.ChangeTracker.Entries<TToken>()
             where string.Equals(entry.Entity.ReferenceId, identifier, StringComparison.Ordinal)
             select entry.Entity).FirstOrDefault();

        Task<TToken?> QueryAsync() =>
            (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization).AsTracking()
             where token.ReferenceId == identifier
             select token).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization).AsTracking()
                where token.Subject == subject
                select token).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetApplicationIdAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        // If the application is not attached to the token, try to load it manually.
        if (token.Application is null)
        {
            var reference = Context.Entry(token).Reference(entry => entry.Application);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (token.Application is null)
        {
            return null;
        }

        return ConvertIdentifierToString(token.Application.Id);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return await query(Tokens.Include(token => token.Application)
            .Include(token => token.Authorization)
            .AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetAuthorizationIdAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        // If the authorization is not attached to the token, try to load it manually.
        if (token.Authorization is null)
        {
            var reference = Context.Entry(token).Reference(entry => entry.Authorization);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (token.Authorization is null)
        {
            return null;
        }

        return ConvertIdentifierToString(token.Authorization.Id);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (token.CreationDate is null)
        {
            return new(result: null);
        }

        return new(DateTime.SpecifyKind(token.CreationDate.Value, DateTimeKind.Utc));
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetExpirationDateAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (token.ExpirationDate is null)
        {
            return new(result: null);
        }

        return new(DateTime.SpecifyKind(token.ExpirationDate.Value, DateTimeKind.Utc));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return new(ConvertIdentifierToString(token.Id));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetPayloadAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return new(token.Payload);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (string.IsNullOrEmpty(token.Properties))
        {
            return new(ImmutableDictionary.Create<string, JsonElement>());
        }

        // Note: parsing the stringified properties is an expensive operation.
        // To mitigate that, the resulting object is stored in the memory cache.
        var key = string.Concat("d0509397-1bbf-40e7-97e1-5e6d7bc2536c", "\x1e", token.Properties);
        var properties = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(token.Properties);
            var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();

            foreach (var property in document.RootElement.EnumerateObject())
            {
                builder[property.Name] = property.Value.Clone();
            }

            return builder.ToImmutable();
        })!;

        return new(properties);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetRedemptionDateAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (token.RedemptionDate is null)
        {
            return new(result: null);
        }

        return new(DateTime.SpecifyKind(token.RedemptionDate.Value, DateTimeKind.Utc));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetReferenceIdAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return new(token.ReferenceId);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return new(token.Status);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetSubjectAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return new(token.Subject);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetTypeAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        return new(token.Type);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TToken> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TToken>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TToken>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0248), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
    {
        var query = Tokens.Include(token => token.Application)
                          .Include(token => token.Authorization)
                          .OrderBy(token => token.Id!)
                          .AsTracking();

        if (offset.HasValue)
        {
            query = query.Skip(offset.Value);
        }

        if (count.HasValue)
        {
            query = query.Take(count.Value);
        }

        return query.AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return query(
            Tokens.Include(token => token.Application)
                  .Include(token => token.Authorization)
                  .AsTracking(), state).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        List<Exception>? exceptions = null;

        var result = 0L;

        // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
        // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
        // To work around this limitation, the threshold represented as a DateTimeOffset
        // instance is manually converted to a UTC DateTime instance outside the query.
        var date = threshold.UtcDateTime;

        // Note: to avoid sending too many queries, the maximum number of elements
        // that can be removed by a single call to PruneAsync() is deliberately limited.
        for (var index = 0; index < 1_000; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

#if SUPPORTS_BULK_DBSET_OPERATIONS
            if (!Options.CurrentValue.DisableBulkOperations)
            {
                try
                {
                    var count = await
                        (from token in Tokens
                         where token.CreationDate < date
                         where (token.Status != Statuses.Inactive && token.Status != Statuses.Valid) ||
                               (token.Authorization != null && token.Authorization.Status != Statuses.Valid) ||
                                token.ExpirationDate < DateTime.UtcNow
                         orderby token.Id
                         select token).Take(1_000).ExecuteDeleteAsync(cancellationToken);

                    if (count is 0)
                    {
                        break;
                    }

                    // Note: calling DbContext.SaveChangesAsync() is not necessary
                    // with bulk delete operations as they are executed immediately.

                    result += count;
                }

                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    exceptions ??= new List<Exception>(capacity: 1);
                    exceptions.Add(exception);
                }
            }

            else
#endif
            {
                var strategy = Context.Database.CreateExecutionStrategy();
                var count = await strategy.ExecuteAsync(async () =>
                {
                    // To prevent concurrency exceptions from being thrown if an entry is modified
                    // after it was retrieved from the database, the following logic is executed in
                    // a repeatable read transaction, that will put a lock on the retrieved entries
                    // and thus prevent them from being concurrently modified outside this block.
                    using var transaction = await Context.CreateTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);

                    var tokens = await
                        (from token in Tokens.AsTracking()
                         where token.CreationDate < date
                         where (token.Status != Statuses.Inactive && token.Status != Statuses.Valid) ||
                               (token.Authorization != null && token.Authorization.Status != Statuses.Valid) ||
                                token.ExpirationDate < DateTime.UtcNow
                         orderby token.Id
                         select token).Take(1_000).ToListAsync(cancellationToken);

                    if (tokens.Count is not 0)
                    {
                        Context.RemoveRange(tokens);

                        try
                        {
                            await Context.SaveChangesAsync(cancellationToken);
                            transaction?.Commit();
                        }

                        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                        {
                            exceptions ??= [];
                            exceptions.Add(exception);
                        }
                    }

                    return tokens.Count;
                });

                if (count is 0)
                {
                    break;
                }

                result += count;
            }
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string ?type, CancellationToken cancellationToken)
    {
        IQueryable<TToken> query = Options.CurrentValue.DisableBulkOperations ?
            Tokens.Include(token => token.Application).Include(token => token.Authorization).AsTracking() :
            Tokens;

        if (!string.IsNullOrEmpty(subject))
        {
            query = query.Where(token => token.Subject == subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations
            // can't be filtered using authorization.Application.Id.Equals(key). To work around
            // this issue, this query uses use an explicit join to apply the equality check.
            //
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.
            var key = ConvertIdentifierFromString(client);

            query = from authorization in query
                    join application in Applications.AsTracking() on authorization.Application!.Id equals application.Id
                    where application.Id!.Equals(key)
                    select authorization;
        }

        if (!string.IsNullOrEmpty(status))
        {
            query = query.Where(token => token.Status == status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            query = query.Where(token => token.Type == type);
        }

#if SUPPORTS_BULK_DBSET_OPERATIONS
        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await query.ExecuteUpdateAsync(entity => entity.SetProperty(
                token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }
#endif
        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await query.ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var key = ConvertIdentifierFromString(identifier);

#if SUPPORTS_BULK_DBSET_OPERATIONS
        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await (
                from token in Tokens
                where token.Application!.Id!.Equals(key)
                select token).ExecuteUpdateAsync(entity => entity.SetProperty(
                    token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }
#endif
        List<Exception>? exceptions = null;

        var result = 0L;

        // Note: due to a bug in Entity Framework Core's query visitor, the tokens
        // can't be filtered using token.Application.Id.Equals(key). To work around
        // this issue, this query uses use an explicit join to apply the equality check.
        //
        // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

        foreach (var token in await (from token in Tokens.Include(token => token.Application)
                                                         .Include(token => token.Authorization)
                                                         .AsTracking()
                                     join application in Applications.AsTracking() on token.Application!.Id equals application.Id
                                     where application.Id!.Equals(key)
                                     select token).ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var key = ConvertIdentifierFromString(identifier);

#if SUPPORTS_BULK_DBSET_OPERATIONS
        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await (
                from token in Tokens
                where token.Authorization!.Id!.Equals(key)
                select token).ExecuteUpdateAsync(entity => entity.SetProperty(
                    token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }
#endif
        List<Exception>? exceptions = null;

        var result = 0L;

        // Note: due to a bug in Entity Framework Core's query visitor, the tokens
        // can't be filtered using token.Authorization.Id.Equals(key). To work around
        // this issue, this query uses use an explicit join to apply the equality check.
        //
        // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

        foreach (var token in await (from token in Tokens.Include(token => token.Application)
                                                         .Include(token => token.Authorization)
                                                         .AsTracking()
                                     join authorization in Authorizations.AsTracking() on token.Authorization!.Id equals authorization.Id
                                     where authorization.Id!.Equals(key)
                                     select token).ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(subject));
        }

#if SUPPORTS_BULK_DBSET_OPERATIONS
        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await (
                from token in Tokens
                where token.Subject == subject
                select token).ExecuteUpdateAsync(entity => entity.SetProperty(
                    token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }
#endif
        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in Tokens.Include(token => token.Application)
                                                         .Include(token => token.Authorization)
                                                         .AsTracking()
                                     where token.Subject == subject
                                     select token).ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetApplicationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (!string.IsNullOrEmpty(identifier))
        {
#if SUPPORTS_DBSET_VALUETASK_FINDASYNC
            token.Application = await Applications.FindAsync([ConvertIdentifierFromString(identifier)], cancellationToken);
#else
            // Warning: when targeting older TFMs, FindAsync() is deliberately not used to work around a breaking
            // change introduced in Entity Framework Core 3.x (where a ValueTask instead of a Task is now returned).

            var key = ConvertIdentifierFromString(identifier);

            token.Application = GetTrackedEntity() ?? await QueryAsync() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0250));

            TApplication? GetTrackedEntity() =>
                (from entry in Context.ChangeTracker.Entries<TApplication>()
                 where entry.Entity.Id is TKey identifier && identifier.Equals(key)
                 select entry.Entity).FirstOrDefault();

            Task<TApplication?> QueryAsync() =>
                (from application in Applications.AsTracking()
                 where application.Id!.Equals(key)
                 select application).FirstOrDefaultAsync(cancellationToken);
#endif
        }

        else
        {
            // If the application is not attached to the token, try to load it manually.
            if (token.Application is null)
            {
                var reference = Context.Entry(token).Reference(entry => entry.Application);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            token.Application = null;
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetAuthorizationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (!string.IsNullOrEmpty(identifier))
        {
#if SUPPORTS_DBSET_VALUETASK_FINDASYNC
            token.Authorization = await Authorizations.FindAsync([ConvertIdentifierFromString(identifier)], cancellationToken);
#else
            // Warning: when targeting older TFMs, FindAsync() is deliberately not used to work around a breaking
            // change introduced in Entity Framework Core 3.x (where a ValueTask instead of a Task is now returned).

            var key = ConvertIdentifierFromString(identifier);

            token.Authorization = GetTrackedEntity() ?? await QueryAsync() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0251));

            TAuthorization? GetTrackedEntity() =>
                (from entry in Context.ChangeTracker.Entries<TAuthorization>()
                 where entry.Entity.Id is TKey identifier && identifier.Equals(key)
                 select entry.Entity).FirstOrDefault();

            Task<TAuthorization?> QueryAsync() =>
                (from authorization in Authorizations.AsTracking()
                 where authorization.Id!.Equals(key)
                 select authorization).FirstOrDefaultAsync(cancellationToken);
#endif
        }

        else
        {
            // If the authorization is not attached to the token, try to load it manually.
            if (token.Authorization is null)
            {
                var reference = Context.Entry(token).Reference(entry => entry.Authorization);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            token.Authorization = null;
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.CreationDate = date?.UtcDateTime;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetExpirationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.ExpirationDate = date?.UtcDateTime;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPayloadAsync(TToken token, string? payload, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.Payload = payload;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TToken token,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        if (properties is not { Count: > 0 })
        {
            token.Properties = null;

            return default;
        }

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        });

        writer.WriteStartObject();

        foreach (var property in properties)
        {
            writer.WritePropertyName(property.Key);
            property.Value.WriteTo(writer);
        }

        writer.WriteEndObject();
        writer.Flush();

        token.Properties = Encoding.UTF8.GetString(stream.ToArray());

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRedemptionDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.RedemptionDate = date?.UtcDateTime;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetReferenceIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.ReferenceId = identifier;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TToken token, string? status, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.Status = status;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSubjectAsync(TToken token, string? subject, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.Subject = subject;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetTypeAsync(TToken token, string? type, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        token.Type = type;

        return default;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        Context.Attach(token);

        // Generate a new concurrency token and attach it
        // to the token before persisting the changes.
        token.ConcurrencyToken = Guid.NewGuid().ToString();

        Context.Update(token);

        try
        {
            await Context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            Context.Entry(token).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0247), exception);
        }
    }

    /// <summary>
    /// Converts the provided identifier to a strongly typed key object.
    /// </summary>
    /// <param name="identifier">The identifier to convert.</param>
    /// <returns>An instance of <typeparamref name="TKey"/> representing the provided identifier.</returns>
    public virtual TKey? ConvertIdentifierFromString(string? identifier)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            return default;
        }

        return (TKey?) TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(identifier);
    }

    /// <summary>
    /// Converts the provided identifier to its string representation.
    /// </summary>
    /// <param name="identifier">The identifier to convert.</param>
    /// <returns>A <see cref="string"/> representation of the provided identifier.</returns>
    public virtual string? ConvertIdentifierToString(TKey? identifier)
    {
        if (Equals(identifier, default(TKey)))
        {
            return null;
        }

        return TypeDescriptor.GetConverter(typeof(TKey)).ConvertToInvariantString(identifier);
    }
}
