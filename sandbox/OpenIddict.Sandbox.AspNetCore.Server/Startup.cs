using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Sandbox.AspNetCore.Server.Models;
using OpenIddict.Sandbox.AspNetCore.Server.Services;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.Server;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddMvc();

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use Microsoft SQL Server.
            options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-aspnetcore-server.sqlite3")}");

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        // Register the Identity services.
        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                // Developers who prefer using MongoDB can remove the previous lines
                // and configure OpenIddict to use the specified MongoDB database:
                // options.UseMongoDb()
                //        .UseDatabase(new MongoClient().GetDatabase("openiddict"));

                // Enable Quartz.NET integration.
                options.UseQuartz();
            })

            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Note: this sample uses the code flow, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableRedirectionEndpointPassthrough();

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(Startup).Assembly);

                // Register the Web providers integrations.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // URI per provider, unless all the registered providers support returning a special "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.UseWebProviders()
                       .AddGitHub(options =>
                       {
                           options.SetClientId("c4ade52327b01ddacff3")
                                  .SetClientSecret("da6bed851b75e317bf6b2cb67013679d9467c122")
                                  .SetRedirectUri("callback/login/github");
                       });
            })

            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                // Enable the endpoints that will be used by the client applications.
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetDeviceAuthorizationEndpointUris("connect/device")
                       .SetEndSessionEndpointUris("connect/endsession")
                       .SetEndUserVerificationEndpointUris("connect/verify")
                       .SetIntrospectionEndpointUris("connect/introspect")
                       .SetPushedAuthorizationEndpointUris("connect/par")
                       .SetRevocationEndpointUris("connect/revoke")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserInfoEndpointUris("connect/userinfo");

                // Enable the flows that will be used by the client applications.
                options.AllowAuthorizationCodeFlow()
                       .AllowDeviceAuthorizationFlow()
                       .AllowHybridFlow()
                       .AllowImplicitFlow()
                       .AllowNoneFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                // Register the public scopes that will be exposed by the configuration endpoint.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "demo_api");

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableEndSessionEndpointPassthrough()
                       .EnableEndUserVerificationEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserInfoEndpointPassthrough();

                // Note: if you don't want to specify a client_id when sending
                // a token or revocation request, uncomment the following line:
                //
                // options.AcceptAnonymousClients();

                // Note: if you want to process authorization and token requests
                // that specify non-registered scopes, uncomment the following line:
                //
                // options.DisableScopeValidation();

                // Note: if you don't want to use permissions, you can disable
                // permission enforcement by uncommenting the following lines:
                //
                // options.IgnoreEndpointPermissions()
                //        .IgnoreGrantTypePermissions()
                //        .IgnoreResponseTypePermissions()
                //        .IgnoreScopePermissions();

                // Note: when issuing access tokens used by third-party APIs
                // you don't own, you can disable access token encryption:
                //
                // options.DisableAccessTokenEncryption();
            })

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // Configure the audience accepted by this resource server.
                // The value MUST match the audience associated with the
                // "demo_api" scope, which is used by ResourceController.
                options.AddAudiences("resource_server");

                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Instead of validating the token locally by reading it directly,
                // introspection can be used to ask a remote authorization server
                // to validate the token (and its attached database entry).
                //
                // options.UseIntrospection()
                //        .SetIssuer("https://localhost:44395/")
                //        .SetClientId("resource_server")
                //        .SetClientSecret("80B552BB-4CD8-48DA-946E-0815E0147DD2");
                //
                // When introspection is used, the System.Net.Http integration must be enabled.
                //
                // options.UseSystemNetHttp();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();

                // For applications that need immediate access token or authorization
                // revocation, the database entry of the received tokens and their
                // associated authorizations can be validated for each API call.
                // Enabling these options may have a negative impact on performance.
                //
                // options.EnableAuthorizationEntryValidation();
                // options.EnableTokenEntryValidation();
            });

        services.AddTransient<IEmailSender, AuthMessageSender>();
        services.AddTransient<ISmsSender, AuthMessageSender>();

        // Register the worker responsible for seeding the database with the sample clients.
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();

        app.UseStaticFiles();

        app.UseStatusCodePagesWithReExecute("/error");

#if SUPPORTS_ENDPOINT_ROUTING
        app.UseRouting();
#endif
        app.UseRequestLocalization(options =>
        {
            options.AddSupportedCultures("en-US", "fr-FR");
            options.AddSupportedUICultures("en-US", "fr-FR");
            options.SetDefaultCulture("en-US");
        });

        app.UseAuthentication();

#if SUPPORTS_AUTHORIZATION_MIDDLEWARE
        app.UseAuthorization();
#endif

#if SUPPORTS_ENDPOINT_ROUTING
        app.UseEndpoints(options =>
        {
            options.MapControllers();
            options.MapDefaultControllerRoute();
        });
#else
        app.UseMvcWithDefaultRoute();
#endif
    }
}
