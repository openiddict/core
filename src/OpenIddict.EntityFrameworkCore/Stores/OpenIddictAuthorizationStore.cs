﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Provides methods allowing to manage the authorizations stored in a database.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    public class OpenIddictAuthorizationStore<TContext> : OpenIddictAuthorizationStore<OpenIddictAuthorization,
                                                                                       OpenIddictApplication,
                                                                                       OpenIddictToken, TContext, string>
        where TContext : DbContext
    {
        public OpenIddictAuthorizationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
            : base(cache, context, options)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the authorizations stored in a database.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictAuthorizationStore<TContext, TKey> : OpenIddictAuthorizationStore<OpenIddictAuthorization<TKey>,
                                                                                             OpenIddictApplication<TKey>,
                                                                                             OpenIddictToken<TKey>, TContext, TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictAuthorizationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
            : base(cache, context, options)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the authorizations stored in a database.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictAuthorizationStore<TAuthorization, TApplication, TToken, TContext, TKey> : IOpenIddictAuthorizationStore<TAuthorization>
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>, new()
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>, new()
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictAuthorizationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        {
            Cache = cache;
            Context = context;
            Options = options;
        }

        /// <summary>
        /// Gets the memory cached associated with the current store.
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

        /// <summary>
        /// Determines the number of authorizations that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of authorizations in the database.
        /// </returns>
        public virtual Task<long> CountAsync(CancellationToken cancellationToken)
            => Authorizations.LongCountAsync();

        /// <summary>
        /// Determines the number of authorizations that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of authorizations that match the specified query.
        /// </returns>
        public virtual Task<long> CountAsync<TResult>([NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(Authorizations).LongCountAsync();
        }

        /// <summary>
        /// Creates a new authorization.
        /// </summary>
        /// <param name="authorization">The authorization to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task CreateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            Context.Add(authorization);

            return Context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Removes an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task DeleteAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            async Task<IDbContextTransaction> CreateTransactionAsync()
            {
                // Note: transactions that specify an explicit isolation level are only supported by
                // relational providers and trying to use them with a different provider results in
                // an invalid operation exception being thrown at runtime. To prevent that, a manual
                // check is made to ensure the underlying transaction manager is relational.
                var manager = Context.Database.GetService<IDbContextTransactionManager>();
                if (manager is IRelationalTransactionManager)
                {
                    try
                    {
                        return await Context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
                    }

                    catch
                    {
                        return null;
                    }
                }

                return null;
            }

            // Note: due to a bug in Entity Framework Core's query visitor, the tokens can't be
            // filtered using token.Application.Id.Equals(key). To work around this issue,
            // this local method uses an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

            Task<List<TToken>> ListTokensAsync()
                => (from token in Tokens.AsTracking()
                    join element in Authorizations.AsTracking() on token.Authorization.Id equals element.Id
                    where element.Id.Equals(authorization.Id)
                    select token).ToListAsync(cancellationToken);

            // To prevent an SQL exception from being thrown if a new associated entity is
            // created after the existing entries have been listed, the following logic is
            // executed in a serializable transaction, that will lock the affected tables.
            using (var transaction = await CreateTransactionAsync())
            {
                // Remove all the tokens associated with the authorization.
                foreach (var token in await ListTokensAsync())
                {
                    Context.Remove(token);
                }

                Context.Remove(authorization);

                try
                {
                    await Context.SaveChangesAsync(cancellationToken);
                    transaction?.Commit();
                }

                catch (DbUpdateConcurrencyException exception)
                {
                    throw new OpenIddictException(OpenIddictConstants.Exceptions.ConcurrencyError, new StringBuilder()
                        .AppendLine("The authorization was concurrently updated and cannot be persisted in its current state.")
                        .Append("Reload the authorization from the database and retry the operation.")
                        .ToString(), exception);
                }
            }
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve the authorizations corresponding
        /// to the specified subject and associated with the application identifier.
        /// </summary>
        private static Func<TContext, TKey, string, AsyncEnumerable<TAuthorization>> FindBySubjectAndClient =
            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations can't be
            // filtered using authorization.Application.Id.Equals(key). To work around this issue,
            // this compiled query uses an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.
            EF.CompileAsyncQuery((TContext context, TKey identifier, string subject) =>
                from authorization in context.Set<TAuthorization>()
                    .Include(authorization => authorization.Application)
                    .AsTracking()
                where authorization.Subject == subject
                join application in context.Set<TApplication>().AsTracking() on authorization.Application.Id equals application.Id
                where application.Id.Equals(identifier)
                select authorization);

        /// <summary>
        /// Retrieves the authorizations corresponding to the specified
        /// subject and associated with the application identifier.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the subject/client.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client cannot be null or empty.", nameof(client));
            }

            return ImmutableArray.CreateRange(await FindBySubjectAndClient(Context,
                ConvertIdentifierFromString(client), subject).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve the authorizations matching the specified parameters.
        /// </summary>
        private static Func<TContext, TKey, string, string, AsyncEnumerable<TAuthorization>> FindBySubjectClientAndStatus =
            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations can't be
            // filtered using authorization.Application.Id.Equals(key). To work around this issue,
            // this compiled query uses an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.
            EF.CompileAsyncQuery((TContext context, TKey identifier, string subject, string status) =>
                from authorization in context.Set<TAuthorization>()
                    .Include(authorization => authorization.Application)
                    .AsTracking()
                where authorization.Subject == subject && authorization.Status == status
                join application in context.Set<TApplication>().AsTracking() on authorization.Application.Id equals application.Id
                where application.Id.Equals(identifier)
                select authorization);

        /// <summary>
        /// Retrieves the authorizations matching the specified parameters.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="status">The authorization status.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the criteria.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client,
            [NotNull] string status, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException("The status cannot be null or empty.", nameof(status));
            }

            return ImmutableArray.CreateRange(await FindBySubjectClientAndStatus(Context,
                ConvertIdentifierFromString(client), subject, status).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve the authorizations matching the specified parameters.
        /// </summary>
        private static Func<TContext, TKey, string, string, string, AsyncEnumerable<TAuthorization>> FindBySubjectClientStatusAndType =
            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations can't be
            // filtered using authorization.Application.Id.Equals(key). To work around this issue,
            // this compiled query uses an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.
            EF.CompileAsyncQuery((TContext context, TKey identifier, string subject, string status, string type) =>
                from authorization in context.Set<TAuthorization>()
                    .Include(authorization => authorization.Application)
                    .AsTracking()
                where authorization.Subject == subject &&
                      authorization.Status == status &&
                      authorization.Type == type
                join application in context.Set<TApplication>().AsTracking() on authorization.Application.Id equals application.Id
                where application.Id.Equals(identifier)
                select authorization);

        /// <summary>
        /// Retrieves the authorizations matching the specified parameters.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="status">The authorization status.</param>
        /// <param name="type">The authorization type.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the criteria.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client,
            [NotNull] string status, [NotNull] string type, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException("The status cannot be null or empty.", nameof(status));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The type cannot be null or empty.", nameof(type));
            }

            return ImmutableArray.CreateRange(await FindBySubjectClientStatusAndType(Context,
                ConvertIdentifierFromString(client), subject, status, type).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve an authorization using its unique identifier.
        /// </summary>
        private static Func<TContext, TKey, Task<TAuthorization>> FindById =
            EF.CompileAsyncQuery((TContext context, TKey identifier) =>
                (from authorization in context.Set<TAuthorization>()
                    .Include(authorization => authorization.Application)
                    .AsTracking()
                 where authorization.Id.Equals(identifier)
                 select authorization).FirstOrDefault());

        /// <summary>
        /// Retrieves an authorization using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorization corresponding to the identifier.
        /// </returns>
        public virtual Task<TAuthorization> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            return FindById(Context, ConvertIdentifierFromString(identifier));
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve all the
        /// authorizations corresponding to the specified subject.
        /// </summary>
        private static Func<TContext, string, AsyncEnumerable<TAuthorization>> FindBySubject =
            EF.CompileAsyncQuery((TContext context, string subject) =>
                from authorization in context.Set<TAuthorization>()
                    .Include(authorization => authorization.Application)
                    .AsTracking()
                where authorization.Subject == subject
                select authorization);

        /// <summary>
        /// Retrieves .
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the specified subject.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindBySubjectAsync(
            [NotNull] string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            return ImmutableArray.CreateRange(await FindBySubject(Context, subject).ToListAsync(cancellationToken));
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
        public virtual async ValueTask<string> GetApplicationIdAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            // If the application is not attached to the authorization, try to load it manually.
            if (authorization.Application == null)
            {
                var reference = Context.Entry(authorization).Reference(entry => entry.Application);
                if (reference.EntityEntry.State == EntityState.Detached)
                {
                    return null;
                }

                await reference.LoadAsync(cancellationToken);
            }

            if (authorization.Application == null)
            {
                return null;
            }

            return ConvertIdentifierToString(authorization.Application.Id);
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
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
        /// </returns>
        public virtual Task<TResult> GetAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(
                Authorizations.Include(authorization => authorization.Application)
                              .AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
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
        public virtual ValueTask<string> GetIdAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(ConvertIdentifierToString(authorization.Id));
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
        public virtual ValueTask<JObject> GetPropertiesAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (string.IsNullOrEmpty(authorization.Properties))
            {
                return new ValueTask<JObject>(new JObject());
            }

            return new ValueTask<JObject>(JObject.Parse(authorization.Properties));
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
        public virtual ValueTask<ImmutableArray<string>> GetScopesAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (string.IsNullOrEmpty(authorization.Scopes))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            return new ValueTask<ImmutableArray<string>>(JArray.Parse(authorization.Scopes).Select(element => (string) element).ToImmutableArray());
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
        public virtual ValueTask<string> GetStatusAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Status);
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
        public virtual ValueTask<string> GetSubjectAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Subject);
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
        public virtual ValueTask<string> GetTypeAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Type);
        }

        /// <summary>
        /// Instantiates a new authorization.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the instantiated authorization, that can be persisted in the database.
        /// </returns>
        public virtual ValueTask<TAuthorization> InstantiateAsync(CancellationToken cancellationToken)
            => new ValueTask<TAuthorization>(Activator.CreateInstance<TAuthorization>());

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> ListAsync(
            [CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            var query = Authorizations.Include(authorization => authorization.Application)
                                      .OrderBy(authorization => authorization.Id)
                                      .AsQueryable();

            if (offset.HasValue)
            {
                query = query.Skip(offset.Value);
            }

            if (count.HasValue)
            {
                query = query.Take(count.Value);
            }

            return ImmutableArray.CreateRange(await query.ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual async Task<ImmutableArray<TResult>> ListAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return ImmutableArray.CreateRange(await query(
                Authorizations.Include(authorization => authorization.Application)
                              .AsTracking(), state).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Removes the ad-hoc authorizations that are marked as invalid or have no valid token attached.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task PruneAsync(CancellationToken cancellationToken)
        {
            // Note: Entity Framework Core doesn't support set-based deletes, which prevents removing
            // entities in a single command without having to retrieve and materialize them first.
            // To work around this limitation, entities are manually listed and deleted using a batch logic.

            IList<Exception> exceptions = null;

            async Task<IDbContextTransaction> CreateTransactionAsync()
            {
                // Note: transactions that specify an explicit isolation level are only supported by
                // relational providers and trying to use them with a different provider results in
                // an invalid operation exception being thrown at runtime. To prevent that, a manual
                // check is made to ensure the underlying transaction manager is relational.
                var manager = Context.Database.GetService<IDbContextTransactionManager>();
                if (manager is IRelationalTransactionManager)
                {
                    // Note: relational providers like Sqlite are known to lack proper support
                    // for repeatable read transactions. To ensure this method can be safely used
                    // with such providers, the database transaction is created in a try/catch block.
                    try
                    {
                        return await Context.Database.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
                    }

                    catch
                    {
                        return null;
                    }
                }

                return null;
            }

            for (var offset = 0; offset < 100_000; offset = offset + 1_000)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // To prevent concurrency exceptions from being thrown if an entry is modified
                // after it was retrieved from the database, the following logic is executed in
                // a repeatable read transaction, that will put a lock on the retrieved entries
                // and thus prevent them from being concurrently modified outside this block.
                using (var transaction = await CreateTransactionAsync())
                {
                    var authorizations =
                        await (from authorization in Authorizations.Include(authorization => authorization.Tokens).AsTracking()
                               where authorization.Status != OpenIddictConstants.Statuses.Valid ||
                                    (authorization.Type == OpenIddictConstants.AuthorizationTypes.AdHoc &&
                                    !authorization.Tokens.Any(token => token.Status == OpenIddictConstants.Statuses.Valid))
                               orderby authorization.Id
                               select authorization).Skip(offset).Take(1_000).ToListAsync(cancellationToken);

                    if (authorizations.Count == 0)
                    {
                        break;
                    }

                    // Note: new tokens may be attached after the authorizations were retrieved
                    // from the database since the transaction level is deliberately limited to
                    // repeatable read instead of serializable for performance reasons). In this
                    // case, the operation will fail, which is considered an acceptable risk.
                    Context.RemoveRange(authorizations);
                    Context.RemoveRange(authorizations.SelectMany(authorization => authorization.Tokens));

                    try
                    {
                        await Context.SaveChangesAsync(cancellationToken);
                        transaction?.Commit();
                    }

                    catch (Exception exception)
                    {
                        if (exceptions == null)
                        {
                            exceptions = new List<Exception>(capacity: 1);
                        }

                        exceptions.Add(exception);
                    }
                }
            }

            if (exceptions != null)
            {
                throw new AggregateException("An error occurred while pruning authorizations.", exceptions);
            }
        }

        /// <summary>
        /// Sets the application identifier associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="identifier">The unique identifier associated with the client application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task SetApplicationIdAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string identifier, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (!string.IsNullOrEmpty(identifier))
            {
                var application = await Applications.FindAsync(new object[] { ConvertIdentifierFromString(identifier) }, cancellationToken);
                if (application == null)
                {
                    throw new InvalidOperationException("The application associated with the authorization cannot be found.");
                }

                authorization.Application = application;
            }

            else
            {
                // If the application is not attached to the authorization, try to load it manually.
                if (authorization.Application == null)
                {
                    var reference = Context.Entry(authorization).Reference(entry => entry.Application);
                    if (reference.EntityEntry.State == EntityState.Detached)
                    {
                        return;
                    }

                    await reference.LoadAsync(cancellationToken);
                }

                authorization.Application = null;
            }
        }

        /// <summary>
        /// Sets the additional properties associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="properties">The additional properties associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetPropertiesAsync([NotNull] TAuthorization authorization, [CanBeNull] JObject properties, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (properties == null)
            {
                authorization.Properties = null;

                return Task.CompletedTask;
            }

            authorization.Properties = properties.ToString(Formatting.None);

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the scopes associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="scopes">The scopes associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetScopesAsync([NotNull] TAuthorization authorization,
            ImmutableArray<string> scopes, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (scopes.IsDefaultOrEmpty)
            {
                authorization.Scopes = null;

                return Task.CompletedTask;
            }

            authorization.Scopes = new JArray(scopes.ToArray()).ToString(Formatting.None);

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the status associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="status">The status associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetStatusAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string status, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.Status = status;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the subject associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetSubjectAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string subject, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.Subject = subject;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the type associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="type">The type associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetTypeAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string type, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.Type = type;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task UpdateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            Context.Attach(authorization);

            // Generate a new concurrency token and attach it
            // to the authorization before persisting the changes.
            authorization.ConcurrencyToken = Guid.NewGuid().ToString();

            Context.Update(authorization);

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException exception)
            {
                throw new OpenIddictException(OpenIddictConstants.Exceptions.ConcurrencyError, new StringBuilder()
                    .AppendLine("The authorization was concurrently updated and cannot be persisted in its current state.")
                    .Append("Reload the authorization from the database and retry the operation.")
                    .ToString(), exception);
            }
        }

        /// <summary>
        /// Converts the provided identifier to a strongly typed key object.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided identifier.</returns>
        public virtual TKey ConvertIdentifierFromString([CanBeNull] string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return default;
            }

            return (TKey) TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(identifier);
        }

        /// <summary>
        /// Converts the provided identifier to its string representation.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>A <see cref="string"/> representation of the provided identifier.</returns>
        public virtual string ConvertIdentifierToString([CanBeNull] TKey identifier)
        {
            if (Equals(identifier, default(TKey)))
            {
                return null;
            }

            return TypeDescriptor.GetConverter(typeof(TKey)).ConvertToInvariantString(identifier);
        }
    }
}