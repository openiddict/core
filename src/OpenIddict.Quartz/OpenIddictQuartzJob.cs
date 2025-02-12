/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;

namespace OpenIddict.Quartz;

/// <summary>
/// Represents a Quartz.NET job performing scheduled tasks for OpenIddict.
/// </summary>
[DisallowConcurrentExecution, EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictQuartzJob : IJob
{
    private readonly IOptionsMonitor<OpenIddictQuartzOptions> _options;
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictQuartzJob"/> class.
    /// </summary>
    public OpenIddictQuartzJob() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0082));

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictQuartzJob"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict Quartz.NET options.</param>
    /// <param name="provider">The service provider.</param>
    public OpenIddictQuartzJob(IOptionsMonitor<OpenIddictQuartzOptions> options, IServiceProvider provider)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Gets the default identity assigned to this job.
    /// </summary>
    public static JobKey Identity { get; } = new JobKey(
        name: SR.GetResourceString(SR.ID8003),
        group: SR.GetResourceString(SR.ID8005));

    /// <inheritdoc/>
    public async Task Execute(IJobExecutionContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        List<Exception>? exceptions = null;

        // Note: this job is registered as a transient service. As such, it cannot directly depend on scoped services
        // like the core managers. To work around this limitation, a scope is manually created for each invocation.
        var scope = _provider.CreateScope();

        try
        {
            // Important: since authorizations that still have tokens attached are never
            // pruned, the tokens MUST be deleted before deleting the authorizations.

            if (!_options.CurrentValue.DisableTokenPruning)
            {
                var manager = scope.ServiceProvider.GetService<IOpenIddictTokenManager>() ??
                    throw new JobExecutionException(new InvalidOperationException(SR.GetResourceString(SR.ID0278)))
                    {
                        RefireImmediately = false,
                        UnscheduleAllTriggers = true,
                        UnscheduleFiringTrigger = true
                    };

                var threshold = (
#if SUPPORTS_TIME_PROVIDER
                    _options.CurrentValue.TimeProvider?.GetUtcNow() ??
#endif
                    DateTimeOffset.UtcNow) - _options.CurrentValue.MinimumTokenLifespan;

                try
                {
                    await manager.PruneAsync(threshold, context.CancellationToken);
                }

                // OperationCanceledExceptions are typically thrown when the host is about to shut down.
                // To allow the host to shut down as fast as possible, this exception type is special-cased
                // to prevent further processing in this job and inform Quartz.NET it shouldn't be refired.
                catch (OperationCanceledException exception) when (context.CancellationToken.IsCancellationRequested)
                {
                    throw new JobExecutionException(exception)
                    {
                        RefireImmediately = false
                    };
                }

                // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
                // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
                catch (AggregateException exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    exceptions ??= [];
                    exceptions.AddRange(exception.InnerExceptions);
                }

                // Other non-fatal exceptions are assumed to be transient and are added to the exceptions collection
                // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    exceptions ??= [];
                    exceptions.Add(exception);
                }
            }

            if (!_options.CurrentValue.DisableAuthorizationPruning)
            {
                var manager = scope.ServiceProvider.GetService<IOpenIddictAuthorizationManager>() ??
                    throw new JobExecutionException(new InvalidOperationException(SR.GetResourceString(SR.ID0278)))
                    {
                        RefireImmediately = false,
                        UnscheduleAllTriggers = true,
                        UnscheduleFiringTrigger = true
                    };

                var threshold = (
#if SUPPORTS_TIME_PROVIDER
                    _options.CurrentValue.TimeProvider?.GetUtcNow() ??
#endif
                    DateTimeOffset.UtcNow) - _options.CurrentValue.MinimumAuthorizationLifespan;

                try
                {
                    await manager.PruneAsync(threshold, context.CancellationToken);
                }

                // OperationCanceledExceptions are typically thrown when the host is about to shut down.
                // To allow the host to shut down as fast as possible, this exception type is special-cased
                // to prevent further processing in this job and inform Quartz.NET it shouldn't be refired.
                catch (OperationCanceledException exception) when (context.CancellationToken.IsCancellationRequested)
                {
                    throw new JobExecutionException(exception)
                    {
                        RefireImmediately = false
                    };
                }

                // AggregateExceptions are generally thrown by the manager itself when one or multiple exception(s)
                // occurred while trying to prune the entities. In this case, add the inner exceptions to the collection.
                catch (AggregateException exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    exceptions ??= [];
                    exceptions.AddRange(exception.InnerExceptions);
                }

                // Other non-fatal exceptions are assumed to be transient and are added to the exceptions collection
                // to be re-thrown later (typically, at the very end of this job, as an AggregateException).
                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    exceptions ??= [];
                    exceptions.Add(exception);
                }
            }

            if (exceptions is not null)
            {
                throw new JobExecutionException(new AggregateException(exceptions))
                {
                    // Only refire the job if the maximum refire count set in the options wasn't reached.
                    RefireImmediately = context.RefireCount < _options.CurrentValue.MaximumRefireCount
                };
            }
        }

        finally
        {
            if (scope is IAsyncDisposable disposable)
            {
                await disposable.DisposeAsync();
            }

            else
            {
                scope.Dispose();
            }
        }
    }
}
