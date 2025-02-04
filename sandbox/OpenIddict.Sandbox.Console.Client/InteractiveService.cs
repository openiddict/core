using System.Security.Claims;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using Spectre.Console;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;

#if !SUPPORTS_HOST_APPLICATION_LIFETIME
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace OpenIddict.Sandbox.Console.Client;

public class InteractiveService : BackgroundService
{
    private readonly IHostApplicationLifetime _lifetime;
    private readonly OpenIddictClientService _service;

    public InteractiveService(
        IHostApplicationLifetime lifetime,
        OpenIddictClientService service)
    {
        _lifetime = lifetime;
        _service = service;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Wait for the host to confirm that the application has started.
        var source = new TaskCompletionSource<bool>();
        using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
        {
            await source.Task;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var provider = await GetSelectedProviderAsync(stoppingToken);

            try
            {
                var configuration = await _service.GetServerConfigurationByProviderNameAsync(provider, stoppingToken);

                if (await AuthenticateUserInteractivelyAsync(configuration, stoppingToken))
                {
                    var flow = await GetSelectedFlowAsync(configuration, stoppingToken);

                    AnsiConsole.MarkupLine("[cyan]Launching the system browser.[/]");

                    // Ask OpenIddict to initiate the authentication flow (typically, by starting the system browser).
                    var result = await _service.ChallengeInteractivelyAsync(new()
                    {
                        GrantType = flow.GrantType,
                        CancellationToken = stoppingToken,
                        ProviderName = provider,
                        ResponseType = flow.ResponseType
                    });

                    AnsiConsole.MarkupLine("[cyan]Waiting for the user to approve the authorization demand.[/]");

                    // Wait for the user to complete the authorization process and authenticate the callback request,
                    // which allows resolving all the claims contained in the merged principal created by OpenIddict.
                    var response = await _service.AuthenticateInteractivelyAsync(new()
                    {
                        CancellationToken = stoppingToken,
                        Nonce = result.Nonce
                    });

                    AnsiConsole.MarkupLine("[green]Interactive authentication successful:[/]");
                    AnsiConsole.Write(CreateClaimTable(response.Principal));

                    // If an access token was returned by the authorization server and introspection is
                    // supported by the server, ask the user if the access token should be introspected.
                    if (!string.IsNullOrEmpty(response.BackchannelAccessToken) &&
                        configuration.IntrospectionEndpoint is not null &&
                        await IntrospectAccessTokenAsync(stoppingToken))
                    {
                        AnsiConsole.MarkupLine("[steelblue]Claims extracted from the token introspection response:[/]");
                        AnsiConsole.Write(CreateClaimTable((await _service.IntrospectTokenAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            ProviderName = provider,
                            Token = response.BackchannelAccessToken,
                            TokenTypeHint = TokenTypeHints.AccessToken
                        })).Principal));
                    }

                    // If an access token was returned by the authorization server and revocation is
                    // supported by the server, ask the user if the access token should be revoked.
                    if (!string.IsNullOrEmpty(response.BackchannelAccessToken) &&
                        configuration.RevocationEndpoint is not null &&
                        await RevokeAccessTokenAsync(stoppingToken))
                    {
                        await _service.RevokeTokenAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            ProviderName = provider,
                            Token = response.BackchannelAccessToken,
                            TokenTypeHint = TokenTypeHints.AccessToken
                        });

                        AnsiConsole.MarkupLine("[steelblue]Access token revoked.[/]");
                    }

                    // If a refresh token was returned by the authorization server, ask the user
                    // if the access token should be refreshed using the refresh_token grant.
                    if (!string.IsNullOrEmpty(response.RefreshToken) && await RefreshTokenAsync(stoppingToken))
                    {
                        AnsiConsole.MarkupLine("[steelblue]Claims extracted from the refreshed identity:[/]");
                        AnsiConsole.Write(CreateClaimTable((await _service.AuthenticateWithRefreshTokenAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            ProviderName = provider,
                            RefreshToken = response.RefreshToken
                        })).Principal));
                    }

                    // If the authorization server supports RP-initiated logout,
                    // ask the user if a logout operation should be started.
                    if (configuration.EndSessionEndpoint is not null && await LogOutAsync(stoppingToken))
                    {
                        AnsiConsole.MarkupLine("[cyan]Launching the system browser.[/]");

                        // Ask OpenIddict to initiate the logout flow (typically, by starting the system browser).
                        var nonce = (await _service.SignOutInteractivelyAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            IdentityTokenHint = response.BackchannelIdentityToken ?? response.FrontchannelIdentityToken,
                            ProviderName = provider
                        })).Nonce;

                        AnsiConsole.MarkupLine("[cyan]Waiting for the user to approve the logout demand.[/]");

                        // Wait for the user to complete the logout process and authenticate the callback request.
                        //
                        // Note: in this case, only the claims contained in the state token can be resolved since
                        // the authorization server doesn't return any other user identity during a logout dance.
                        await _service.AuthenticateInteractivelyAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            Nonce = nonce
                        });

                        AnsiConsole.MarkupLine("[green]Interactive logout successful.[/]");
                    }
                }

                else
                {
                    var type = await GetSelectedGrantTypeAsync(configuration, stoppingToken);
                    if (type is GrantTypes.DeviceCode)
                    {
                        // Ask OpenIddict to send a device authorization request and write
                        // the complete verification endpoint URI to the console output.
                        var result = await _service.ChallengeUsingDeviceAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            ProviderName = provider
                        });

                        if (result.VerificationUriComplete is not null)
                        {
                            AnsiConsole.MarkupLineInterpolated($"""
                                [yellow]Please visit [link]{result.VerificationUriComplete}[/] and confirm the
                                displayed code is '{result.UserCode}' to complete the authentication demand.[/]
                                """);
                        }

                        else
                        {
                            AnsiConsole.MarkupLineInterpolated($"""
                                [yellow]Please visit [link]{result.VerificationUri}[/] and enter
                                '{result.UserCode}' to complete the authentication demand.[/]
                                """);
                        }

                        AnsiConsole.MarkupLine("[cyan]Waiting for the user to approve the authorization demand.[/]");

                        // Wait for the user to complete the demand on the other device.
                        var response = await _service.AuthenticateWithDeviceAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            DeviceCode = result.DeviceCode,
                            Interval = result.Interval,
                            ProviderName = provider,
                            Timeout = result.ExpiresIn < TimeSpan.FromMinutes(5) ? result.ExpiresIn : TimeSpan.FromMinutes(5)
                        });

                        AnsiConsole.MarkupLine("[green]Device authentication successful:[/]");
                        AnsiConsole.Write(CreateClaimTable(response.Principal));

                        // If introspection is supported by the server, ask the user if the access token should be introspected.
                        if (configuration.IntrospectionEndpoint is not null && await IntrospectAccessTokenAsync(stoppingToken))
                        {
                            AnsiConsole.MarkupLine("[steelblue]Claims extracted from the token introspection response:[/]");
                            AnsiConsole.Write(CreateClaimTable((await _service.IntrospectTokenAsync(new()
                            {
                                CancellationToken = stoppingToken,
                                ProviderName = provider,
                                Token = response.AccessToken,
                                TokenTypeHint = TokenTypeHints.AccessToken
                            })).Principal));
                        }

                        // If revocation is supported by the server, ask the user if the access token should be revoked.
                        if (configuration.RevocationEndpoint is not null && await RevokeAccessTokenAsync(stoppingToken))
                        {
                            await _service.RevokeTokenAsync(new()
                            {
                                CancellationToken = stoppingToken,
                                ProviderName = provider,
                                Token = response.AccessToken,
                                TokenTypeHint = TokenTypeHints.AccessToken
                            });

                            AnsiConsole.MarkupLine("[steelblue]Access token revoked.[/]");
                        }

                        // If a refresh token was returned by the authorization server, ask the user
                        // if the access token should be refreshed using the refresh_token grant.
                        if (!string.IsNullOrEmpty(response.RefreshToken) && await RefreshTokenAsync(stoppingToken))
                        {
                            AnsiConsole.MarkupLine("[steelblue]Claims extracted from the refreshed identity:[/]");
                            AnsiConsole.Write(CreateClaimTable((await _service.AuthenticateWithRefreshTokenAsync(new()
                            {
                                CancellationToken = stoppingToken,
                                ProviderName = provider,
                                RefreshToken = response.RefreshToken
                            })).Principal));
                        }
                    }

                    else if (type is GrantTypes.Password)
                    {
                        var (username, password) = (await GetUsernameAsync(stoppingToken), await GetPasswordAsync(stoppingToken));

                        AnsiConsole.MarkupLine("[cyan]Sending the token request.[/]");

                        // Ask OpenIddict to authenticate the user using the resource owner password credentials grant.
                        var response = await _service.AuthenticateWithPasswordAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            ProviderName = provider,
                            Username = username,
                            Password = password,
                            Scopes = [Scopes.OfflineAccess]
                        });

                        AnsiConsole.MarkupLine("[green]Resource owner password credentials authentication successful:[/]");
                        AnsiConsole.Write(CreateClaimTable(response.Principal));

                        // If introspection is supported by the server, ask the user if the access token should be introspected.
                        if (configuration.IntrospectionEndpoint is not null && await IntrospectAccessTokenAsync(stoppingToken))
                        {
                            AnsiConsole.MarkupLine("[steelblue]Claims extracted from the token introspection response:[/]");
                            AnsiConsole.Write(CreateClaimTable((await _service.IntrospectTokenAsync(new()
                            {
                                CancellationToken = stoppingToken,
                                ProviderName = provider,
                                Token = response.AccessToken,
                                TokenTypeHint = TokenTypeHints.AccessToken
                            })).Principal));
                        }

                        // If revocation is supported by the server, ask the user if the access token should be revoked.
                        if (configuration.RevocationEndpoint is not null && await RevokeAccessTokenAsync(stoppingToken))
                        {
                            await _service.RevokeTokenAsync(new()
                            {
                                CancellationToken = stoppingToken,
                                ProviderName = provider,
                                Token = response.AccessToken,
                                TokenTypeHint = TokenTypeHints.AccessToken
                            });

                            AnsiConsole.MarkupLine("[steelblue]Access token revoked.[/]");
                        }

                        // If a refresh token was returned by the authorization server, ask the user
                        // if the access token should be refreshed using the refresh_token grant.
                        if (!string.IsNullOrEmpty(response.RefreshToken) && await RefreshTokenAsync(stoppingToken))
                        {
                            AnsiConsole.MarkupLine("[steelblue]Claims extracted from the refreshed identity:[/]");
                            AnsiConsole.Write(CreateClaimTable((await _service.AuthenticateWithRefreshTokenAsync(new()
                            {
                                CancellationToken = stoppingToken,
                                ProviderName = provider,
                                RefreshToken = response.RefreshToken
                            })).Principal));
                        }
                    }

                    else if (type is GrantTypes.ClientCredentials)
                    {
                        AnsiConsole.MarkupLine("[cyan]Sending the token request.[/]");

                        // Ask OpenIddict to authenticate the client application using the client credentials grant.
                        await _service.AuthenticateWithClientCredentialsAsync(new()
                        {
                            CancellationToken = stoppingToken,
                            ProviderName = provider
                        });

                        AnsiConsole.MarkupLine("[green]Client credentials authentication successful.[/]");
                    }
                }
            }

            catch (OperationCanceledException)
            {
                AnsiConsole.MarkupLine("[red]The authentication process was aborted.[/]");
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                AnsiConsole.MarkupLine("[yellow]The authorization was denied by the end user.[/]");
            }

            catch (Exception exception)
            {
                AnsiConsole.MarkupLine("[red]An error occurred while trying to authenticate the user:[/]");
                AnsiConsole.WriteException(exception);
            }
        }

        static Table CreateClaimTable(ClaimsPrincipal principal)
        {
            var table = new Table()
                .LeftAligned()
                .AddColumn("Claim type")
                .AddColumn("Claim value type")
                .AddColumn("Claim value")
                .AddColumn("Claim issuer");

            foreach (var claim in principal.Claims)
            {
                table.AddRow(
                    claim.Type.EscapeMarkup(),
                    claim.ValueType.EscapeMarkup(),
                    claim.Value.EscapeMarkup(),
                    claim.Issuer.EscapeMarkup());
            }

            return table;
        }

        Task<string> GetSelectedProviderAsync(CancellationToken cancellationToken)
        {
            async Task<string> PromptAsync() => AnsiConsole.Prompt(new SelectionPrompt<OpenIddictClientRegistration>()
                .Title("Select the authentication provider you'd like to log in with.")
                .AddChoices(from registration in await _service.GetClientRegistrationsAsync(stoppingToken)
                            where !string.IsNullOrEmpty(registration.ProviderName)
                            where !string.IsNullOrEmpty(registration.ProviderDisplayName)
                            select registration)
                .UseConverter(registration => registration.ProviderDisplayName!)).ProviderName!;

            return WaitAsync(Task.Run(PromptAsync, cancellationToken), cancellationToken);
        }

        Task<(string? GrantType, string? ResponseType)> GetSelectedFlowAsync(
            OpenIddictConfiguration configuration, CancellationToken cancellationToken)
        {
            static (string? GrantType, string? ResponseType) Prompt(OpenIddictConfiguration configuration)
            {
                List<((string? GrantType, string? ResponseType), string DisplayName)> choices = [];

                var types = configuration.ResponseTypesSupported.Select(type =>
                    new HashSet<string>(type.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries)));

                if (configuration.GrantTypesSupported.Contains(GrantTypes.AuthorizationCode) &&
                    types.Any(type => type.Count is 1 && type.Contains(ResponseTypes.Code)))
                {
                    choices.Add(((
                        GrantType   : GrantTypes.AuthorizationCode,
                        ResponseType: ResponseTypes.Code), "Authorization code flow"));
                }

                if (configuration.GrantTypesSupported.Contains(GrantTypes.Implicit))
                {
                    if (types.Any(type => type.Count is 1 && type.Contains(ResponseTypes.IdToken)))
                    {
                        choices.Add(((
                            GrantType   : GrantTypes.Implicit,
                            ResponseType: ResponseTypes.IdToken), "Implicit flow (id_token)"));
                    }

                    if (types.Any(type => type.Count is 2 && type.Contains(ResponseTypes.IdToken) &&
                                                             type.Contains(ResponseTypes.Token)))
                    {
                        choices.Add(((
                            GrantType   : GrantTypes.Implicit,
                            ResponseType: ResponseTypes.IdToken + ' ' + ResponseTypes.Token), "Implicit flow (id_token + token)"));
                    }
                }

                if (configuration.GrantTypesSupported.Contains(GrantTypes.AuthorizationCode) &&
                    configuration.GrantTypesSupported.Contains(GrantTypes.Implicit))
                {
                    if (types.Any(type => type.Count is 2 && type.Contains(ResponseTypes.Code) &&
                                                             type.Contains(ResponseTypes.IdToken)))
                    {
                        choices.Add(((
                            GrantType   : GrantTypes.AuthorizationCode,
                            ResponseType: ResponseTypes.Code + ' ' + ResponseTypes.IdToken), "Hybrid flow (code + id_token)"));
                    }

                    if (types.Any(type => type.Count is 3 && type.Contains(ResponseTypes.Code) &&
                                                             type.Contains(ResponseTypes.IdToken) &&
                                                             type.Contains(ResponseTypes.Token)))
                    {
                        choices.Add(((
                            GrantType   : GrantTypes.AuthorizationCode,
                            ResponseType: ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token),
                            "Hybrid flow (code + id_token + token)"));
                    }

                    if (types.Any(type => type.Count is 2 && type.Contains(ResponseTypes.Code) &&
                                                             type.Contains(ResponseTypes.Token)))
                    {
                        choices.Add(((
                            GrantType   : GrantTypes.AuthorizationCode,
                            ResponseType: ResponseTypes.Code + ' ' + ResponseTypes.Token), "Hybrid flow (code + token)"));
                    }
                }

                if (types.Any(type => type.Count is 1 && type.Contains(ResponseTypes.None)))
                {
                    choices.Add(((
                        GrantType   : null,
                        ResponseType: ResponseTypes.None), "\"None flow\" (no token is returned)"));
                }

                if (choices.Count is 0)
                {
                    throw new NotSupportedException("The selected provider doesn't support any of the flows implemented by this sample.");
                }

                choices.Insert(0, ((null, null), "Let OpenIddict negotiate the best authentication flow"));

                return AnsiConsole.Prompt(new SelectionPrompt<((string? GrantType, string? ResponseType), string DisplayName)>()
                    .Title("Select the user interactive grant type you'd like to use.")
                    .AddChoices(choices)
                    .UseConverter(choice => choice.DisplayName)).Item1;
            }

            return WaitAsync(Task.Run(() => Prompt(configuration), cancellationToken), cancellationToken);
        }

        Task<string> GetSelectedGrantTypeAsync(OpenIddictConfiguration configuration, CancellationToken cancellationToken)
        {
            static string Prompt(OpenIddictConfiguration configuration)
            {
                List<(string GrantType, string DisplayName)> choices = [];

                if (configuration.GrantTypesSupported.Contains(GrantTypes.DeviceCode) &&
                    configuration.DeviceAuthorizationEndpoint is not null &&
                    configuration.TokenEndpoint is not null)
                {
                    choices.Add((GrantTypes.DeviceCode, "Device authorization code grant"));
                }

                if (configuration.GrantTypesSupported.Contains(GrantTypes.Password) &&
                    configuration.TokenEndpoint is not null)
                {
                    choices.Add((GrantTypes.Password, "Resource owner password credentials grant"));
                }

                if (configuration.GrantTypesSupported.Contains(GrantTypes.ClientCredentials) &&
                    configuration.TokenEndpoint is not null)
                {
                    choices.Add((GrantTypes.ClientCredentials, "Client credentials grant (application authentication only)"));
                }

                if (choices.Count is 0)
                {
                    throw new NotSupportedException("The selected provider doesn't support any of the grant types implemented by this sample.");
                }

                return AnsiConsole.Prompt(new SelectionPrompt<(string GrantType, string DisplayName)>()
                    .Title("Select the grant type you'd like to use.")
                    .AddChoices(choices)
                    .UseConverter(choice => choice.DisplayName)).GrantType;
            }

            return WaitAsync(Task.Run(() => Prompt(configuration), cancellationToken), cancellationToken);
        }

        Task<bool> AuthenticateUserInteractivelyAsync(
            OpenIddictConfiguration configuration, CancellationToken cancellationToken)
        {
            static bool Prompt() => AnsiConsole.Prompt(new ConfirmationPrompt(
                "Would you like to use a user-interactive authentication method?")
            {
                Comparer = StringComparer.CurrentCultureIgnoreCase,
                DefaultValue = true,
                ShowDefaultValue = true
            });

            if (configuration.GrantTypesSupported.Contains(GrantTypes.AuthorizationCode) ||
                configuration.GrantTypesSupported.Contains(GrantTypes.Implicit))
            {
                return WaitAsync(Task.Run(Prompt, cancellationToken), cancellationToken);
            }

            return Task.FromResult(false);
        }

        Task<string> GetUsernameAsync(CancellationToken cancellationToken)
        {
            static string Prompt() => AnsiConsole.Prompt(new TextPrompt<string>("Please enter your username:")
            {
                AllowEmpty = false,
                IsSecret = false
            });

            return WaitAsync(Task.Run(Prompt, cancellationToken), cancellationToken);
        }

        Task<string> GetPasswordAsync(CancellationToken cancellationToken)
        {
            static string Prompt() => AnsiConsole.Prompt(new TextPrompt<string>("Please enter your password:")
            {
                AllowEmpty = false,
                IsSecret = true
            });

            return WaitAsync(Task.Run(Prompt, cancellationToken), cancellationToken);
        }

        static Task<bool> RefreshTokenAsync(CancellationToken cancellationToken)
        {
            static bool Prompt() => AnsiConsole.Prompt(new ConfirmationPrompt(
                "Would you like to refresh the user authentication using the refresh token grant?")
            {
                Comparer = StringComparer.CurrentCultureIgnoreCase,
                DefaultValue = false,
                ShowDefaultValue = true
            });

            return WaitAsync(Task.Run(Prompt, cancellationToken), cancellationToken);
        }

        static Task<bool> IntrospectAccessTokenAsync(CancellationToken cancellationToken)
        {
            static bool Prompt() => AnsiConsole.Prompt(new ConfirmationPrompt(
                "Would you like to introspect the access token?")
            {
                Comparer = StringComparer.CurrentCultureIgnoreCase,
                DefaultValue = false,
                ShowDefaultValue = true
            });

            return WaitAsync(Task.Run(Prompt, cancellationToken), cancellationToken);
        }

        static Task<bool> LogOutAsync(CancellationToken cancellationToken)
        {
            static bool Prompt() => AnsiConsole.Prompt(new ConfirmationPrompt("Would you like to log out?")
            {
                Comparer = StringComparer.CurrentCultureIgnoreCase,
                DefaultValue = false,
                ShowDefaultValue = true
            });

            return WaitAsync(Task.Run(Prompt, cancellationToken), cancellationToken);
        }

        static Task<bool> RevokeAccessTokenAsync(CancellationToken cancellationToken)
        {
            static bool Prompt() => AnsiConsole.Prompt(new ConfirmationPrompt(
                "Would you like to revoke the access token?")
            {
                Comparer = StringComparer.CurrentCultureIgnoreCase,
                DefaultValue = false,
                ShowDefaultValue = true
            });

            return WaitAsync(Task.Run(Prompt, cancellationToken), cancellationToken);
        }

        static async Task<T> WaitAsync<T>(Task<T> task, CancellationToken cancellationToken)
        {
#if SUPPORTS_TASK_WAIT_ASYNC
            return await task.WaitAsync(cancellationToken);
#else
            var source = new TaskCompletionSource<bool>(TaskCreationOptions.None);

            using (cancellationToken.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
            {
                if (await Task.WhenAny(task, source.Task) == source.Task)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                return await task;
            }
#endif
        }
    }
}
