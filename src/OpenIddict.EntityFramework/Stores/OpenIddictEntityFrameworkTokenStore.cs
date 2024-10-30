/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Data;
using System.Data.Entity.Infrastructure;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFramework.Models;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
public class OpenIddictEntityFrameworkTokenStore<TContext> :
    OpenIddictEntityFrameworkTokenStore<OpenIddictEntityFrameworkToken,
                                        OpenIddictEntityFrameworkApplication,
                                        OpenIddictEntityFrameworkAuthorization, TContext, string>
    where TContext : DbContext
{
    public OpenIddictEntityFrameworkTokenStore(
        IMemoryCache cache,
        TContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
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
public class OpenIddictEntityFrameworkTokenStore<TToken, TApplication, TAuthorization, TContext, TKey> : IOpenIddictTokenStore<TToken>
    where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
    where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
    where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
    where TContext : DbContext
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkTokenStore(
        IMemoryCache cache,
        TContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
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
    protected IOptionsMonitor<OpenIddictEntityFrameworkOptions> Options { get; }

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
        => await Tokens.LongCountAsync(cancellationToken);

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

        Tokens.Add(token);

        await Context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TToken token, CancellationToken cancellationToken)
    {
        if (token is null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        Tokens.Remove(token);

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
    public virtual IAsyncEnumerable<TToken> FindAsync(string subject,
        string client, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        var key = ConvertIdentifierFromString(client);

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
                where token.Application!.Id!.Equals(key) &&
                      token.Subject == subject
                select token).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindAsync(
        string subject, string client,
        string status, CancellationToken cancellationToken)
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

        var key = ConvertIdentifierFromString(client);

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
                where token.Application!.Id!.Equals(key) &&
                      token.Subject == subject &&
                      token.Status == status
                select token).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindAsync(
        string subject, string client,
        string status, string type, CancellationToken cancellationToken)
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

        var key = ConvertIdentifierFromString(client);

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
                where token.Application!.Id!.Equals(key) &&
                      token.Subject == subject &&
                      token.Status == status &&
                      token.Type == type
                select token).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var key = ConvertIdentifierFromString(identifier);

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
                where token.Application!.Id!.Equals(key)
                select token).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var key = ConvertIdentifierFromString(identifier);

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
                where token.Authorization!.Id!.Equals(key)
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
            (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
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
            (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
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

        return (from token in Tokens.Include(token => token.Application).Include(token => token.Authorization)
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

        return await query(
            Tokens.Include(token => token.Application)
                  .Include(token => token.Authorization), state).FirstOrDefaultAsync(cancellationToken);
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
                          .AsQueryable();

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
                  .Include(token => token.Authorization), state).AsAsyncEnumerable(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        // Note: Entity Framework 6.x doesn't support set-based deletes, which prevents removing
        // entities in a single command without having to retrieve and materialize them first.
        // To work around this limitation, entities are manually listed and deleted using a batch logic.

        List<Exception>? exceptions = null;

        var result = 0L;

        // Note: to avoid sending too many queries, the maximum number of elements
        // that can be removed by a single call to PruneAsync() is deliberately limited.
        for (var index = 0; index < 1_000; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // To prevent concurrency exceptions from being thrown if an entry is modified
            // after it was retrieved from the database, the following logic is executed in
            // a repeatable read transaction, that will put a lock on the retrieved entries
            // and thus prevent them from being concurrently modified outside this block.
            using var transaction = Context.CreateTransaction(IsolationLevel.RepeatableRead);

            // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
            // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
            // To work around this limitation, the threshold represented as a DateTimeOffset
            // instance is manually converted to a UTC DateTime instance outside the query.
            var date = threshold.UtcDateTime;

            var tokens = await
                (from token in Tokens
                 where token.CreationDate < date
                 where (token.Status != Statuses.Inactive && token.Status != Statuses.Valid) ||
                       (token.Authorization != null && token.Authorization.Status != Statuses.Valid) ||
                        token.ExpirationDate < DateTime.UtcNow
                 orderby token.Id
                 select token).Take(1_000).ToListAsync(cancellationToken);

            if (tokens.Count is 0)
            {
                break;
            }

            Tokens.RemoveRange(tokens);

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
                transaction?.Commit();
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result += tokens.Count;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeAsync(string subject, string client, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        var key = ConvertIdentifierFromString(client);

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in Tokens
                                     where token.Application!.Id!.Equals(key) && token.Subject == subject
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
    public virtual async ValueTask<long> RevokeAsync(string subject, string client, string status, CancellationToken cancellationToken)
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

        var key = ConvertIdentifierFromString(client);

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in Tokens
                                     where token.Application!.Id!.Equals(key) &&
                                           token.Subject == subject &&
                                           token.Status == status
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
    public virtual async ValueTask<long> RevokeAsync(string subject, string client, string status, string type, CancellationToken cancellationToken)
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

        var key = ConvertIdentifierFromString(client);

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in Tokens
                                     where token.Application!.Id!.Equals(key) &&
                                           token.Subject == subject &&
                                           token.Status == status &&
                                           token.Type == type
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
    public virtual async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var key = ConvertIdentifierFromString(identifier);

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in Tokens
                                     where token.Application!.Id!.Equals(key)
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

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in Tokens
                                     where token.Authorization!.Id!.Equals(key)
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

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in Tokens
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
            token.Application = await Applications.FindAsync(
                cancellationToken, ConvertIdentifierFromString(identifier)) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0250));
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
            token.Authorization = await Authorizations.FindAsync(
                cancellationToken, ConvertIdentifierFromString(identifier)) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0251));
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

        Tokens.Attach(token);

        // Generate a new concurrency token and attach it
        // to the token before persisting the changes.
        token.ConcurrencyToken = Guid.NewGuid().ToString();

        Context.Entry(token).State = EntityState.Modified;

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
