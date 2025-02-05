using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;
using OpenIddict.Sandbox.Console.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

var host = new HostBuilder()
    // Note: applications for which a single instance is preferred can reference
    // the Dapplo.Microsoft.Extensions.Hosting.AppServices package and call this
    // method to automatically close extra instances based on the specified identifier:
    //
    // .ConfigureSingleInstance(options => options.MutexId = "{802A478D-00E8-4DAE-9A27-27B31A47CB39}")
    //
    .ConfigureLogging(options => options.AddDebug())
    .ConfigureServices(services =>
    {
        services.AddDbContext<DbContext>(options =>
        {
            options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-console-client.sqlite3")}");
            options.UseOpenIddict();
        });

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<DbContext>();
            })

            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Note: this sample enables all the supported flows but
                // you can restrict the list of enabled flows if necessary.
                options.AllowAuthorizationCodeFlow()
                       .AllowClientCredentialsFlow()
                       .AllowDeviceAuthorizationFlow()
                       .AllowHybridFlow()
                       .AllowImplicitFlow()
                       .AllowNoneFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Add the operating system integration.
                options.UseSystemIntegration()
                       .DisableActivationHandling()
                       .DisableActivationRedirection()
                       .DisablePipeServer()
                       .EnableEmbeddedWebServer()
                       .UseSystemBrowser()
                       .SetApplicationDiscriminator("0XP3WQ07VVMCVBJ")
                       .SetAllowedEmbeddedWebServerPorts(49152, 49153, 49154);

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(Program).Assembly);

                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://localhost:44395/", UriKind.Absolute),
                    ProviderName = "Local",
                    ProviderDisplayName = "Local authorization server",

                    ClientId = "console",

                    PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative),
                    RedirectUri = new Uri("callback/login/local", UriKind.Relative),

                    Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
                });

                // Register the Web providers integrations.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // address per provider, unless all the registered providers support returning an "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.UseWebProviders()
                       .AddGitHub(options =>
                       {
                           options.SetClientId("992372d088f8676a7945")
                                  .SetClientSecret("1f18c22f766e44d7bd4ea4a6510b9e337d48ab38")
                                  .SetRedirectUri("callback/login/github");
                       })
                       .AddYandex(options =>
                       {
                           options.SetClientId("319737032de44c73b2bbaf81a184e742");
                           options.SetClientSecret("f01e34a090564b60ae78629616f581db");
                           options.SetRedirectUri("callback/login/yandex");
                           options.AddScopes(
                               "login:email",
                               "login:info"
                           );
                       })
                       .AddVkId(options =>
                       {
                           options.SetClientId("52043315");
                           options.SetClientSecret("0jZ74hcVM1e6nesBsa27");
                           options.SetRedirectUri("callback/login/vkid");
                           options.AddScopes(
                               "email");
                       })
                       .AddTwitter(options =>
                       {
                           options.SetClientId("bXgwc0U3N3A3YWNuaWVsdlRmRWE6MTpjaQ")
                                  .SetRedirectUri("callback/login/twitter");
                       });
            });

        // Register the worker responsible for creating the database used to store tokens
        // and adding the registry entries required to register the custom URI scheme.
        //
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();

        // Register the background service responsible for handling the console interactions.
        services.AddHostedService<InteractiveService>();

        // Prevent the console lifetime manager from writing status messages to the output stream.
        services.Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true);
    })
    .UseConsoleLifetime()
    .Build();

await host.RunAsync();