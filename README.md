# OpenIddict

### The OpenID Connect stack you'll be addicted to.

[![Build status](https://github.com/openiddict/openiddict-core/workflows/build/badge.svg?branch=dev&event=push)](https://github.com/openiddict/openiddict-core/actions?query=workflow%3Abuild+branch%3Adev+event%3Apush)

## What is OpenIddict?

OpenIddict aims at providing a **versatile solution** to implement **OpenID Connect client, server and token validation support in .NET applications**.

> [!TIP]
> While the client, server and token validation features can be used in any ASP.NET 4.6.1+ or
> [ASP.NET Core 2.1+ web application](https://documentation.openiddict.com/integrations/aspnet-core),
> the client feature can also be used in
> [Android, iOS, Linux, Mac Catalyst, macOS and Windows applications](https://documentation.openiddict.com/integrations/operating-systems)
> to integrate with OpenIddict-based identity providers or any other OAuth 2.0/OpenID Connect-compliant implementation.

OpenIddict fully supports the **[code/implicit/hybrid flows](http://openid.net/specs/openid-connect-core-1_0.html)**,
the **[client credentials/resource owner password grants](https://tools.ietf.org/html/rfc6749)** and the [device authorization flow](https://tools.ietf.org/html/rfc8628).

OpenIddict natively supports **[Entity Framework Core](https://www.nuget.org/packages/OpenIddict.EntityFrameworkCore)**,
**[Entity Framework 6](https://www.nuget.org/packages/OpenIddict.EntityFramework)** and **[MongoDB](https://www.nuget.org/packages/OpenIddict.MongoDb)**
out-of-the-box and custom stores can be implemented to support other providers.

--------------

## Getting started

**To implement a custom OpenID Connect server using OpenIddict, read [Getting started](https://documentation.openiddict.com/guides/getting-started/)**.

**Samples demonstrating how to use OpenIddict with the different OAuth 2.0/OpenID Connect flows**
can be found in the [dedicated repository](https://github.com/openiddict/openiddict-samples).

**Developers looking for a simple and turnkey solution are strongly encouraged to use [OrchardCore and its OpenID module](https://docs.orchardcore.net/en/latest/docs/reference/modules/OpenId/)**,
which is based on OpenIddict, comes with sensible defaults and offers a built-in management GUI to easily register OpenID client applications.

**Looking to integrate with a SAML2P Identity Provider (IDP) or Service Provider (SP)?** Rock Solid Knowledge, a sponsor of OpenIddict, is developing a range of identity components to enhance your OpenIddict solution.
The first of these is their popular [SAML2P component](https://www.openiddictcomponents.com/?utm_source=openiddictgithubmain&utm_campaign=openiddict).

--------------

## Certification

Unlike many other identity providers, **OpenIddict is not a turnkey solution but a framework that requires writing custom code**
to be operational (typically, at least an authorization controller), making it a poor candidate for the certification program.

While a reference implementation could be submitted as-is, **this wouldn't guarantee that implementations deployed by OpenIddict users would be standard-compliant.**

Instead, **developers are encouraged to execute the conformance tests against their own deployment** once they've implemented their own logic.

> [!TIP]
> The samples repository contains [a dedicated sample](https://github.com/openiddict/openiddict-samples/tree/dev/samples/Contruum/Contruum.Server) specially designed to be used
> with the OpenID Connect Provider Certification tool and demonstrate that OpenIddict can be easily used in a certified implementation. To allow executing the certification tests
> as fast as possible, that sample doesn't include any membership or consent feature (two hardcoded identities are proposed for tests that require switching between identities).

--------------

## Resources

**Looking for additional resources to help you get started with OpenIddict?** Don't miss these interesting blog posts:

- **[OpenIddict 6.0 general availability](https://kevinchalet.com/2024/12/17/openiddict-6-0-general-availability/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[OpenIddict on AWS Serverless: Flexible OAuth2/OIDC Provider](https://www.ganhammar.se/posts/openiddict-on-aws-serverless-flexible-oauth2-oidc-provider)** by [Anton Ganhammar](https://github.com/ganhammar)
- **[OpenIddict 5.0 general availability](https://kevinchalet.com/2023/12/18/openiddict-5-0-general-availability/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing native applications, per-client token lifetimes and client assertions support in OpenIddict 5.0 preview1](https://kevinchalet.com/2023/10/20/introducing-native-applications-per-client-token-lifetimes-and-client-assertions-support-in-openiddict-5-0-preview1/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Can you use the ASP.NET Core Identity API endpoints with OpenIddict?](https://kevinchalet.com/2023/10/04/can-you-use-the-asp-net-core-identity-api-endpoints-with-openiddict/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[OpenID Connect and OAuth 2.0 server in ASP.NET Core using OpenIddict](https://medium.com/@sergeygoodgood/openid-connect-and-oauth2-0-server-in-aspnetcore-using-openiddict-c463c6ebc082)** by [Siarhei Kharlap](https://medium.com/@sergeygoodgood)
- **[Transparent Auth Gateway](https://alex-klaus.com/transparent-auth-gateway-1/)** by [Alex Klaus](https://github.com/aklaus)
- **[Introducing system integration support for the OpenIddict client](https://kevinchalet.com/2023/02/27/introducing-system-integration-support-for-the-openiddict-client/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[OpenIddict 4.0 general availability](https://kevinchalet.com/2022/12/23/openiddict-4-0-general-availability/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Getting started with the OpenIddict web providers](https://kevinchalet.com/2022/12/16/getting-started-with-the-openiddict-web-providers/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing the OpenIddict-powered providers](https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers/issues/694)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Introducing the OpenIddict client](https://kevinchalet.com/2022/02/25/introducing-the-openiddict-client/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Secure a Blazor WASM ASP.NET Core hosted APP using BFF and OpenIddict](https://damienbod.com/2022/01/03/secure-a-blazor-wasm-asp-net-core-hosted-app-using-bff-and-openiddict/)** by [Damien Bowden](https://github.com/damienbod)
- **[Setting up an Authorization Server with OpenIddict](https://dev.to/robinvanderknaap/setting-up-an-authorization-server-with-openiddict-part-i-introduction-4jid)** by [Robin van der Knaap](https://dev.to/robinvanderknaap)
- **[Adding OpenIddict 3.0 to an OWIN application](https://kevinchalet.com/2020/03/03/adding-openiddict-3-0-to-an-owin-application/)** by [Kévin Chalet](https://github.com/kevinchalet)
- **[Creating an OpenID Connect server proxy with OpenIddict 3.0's degraded mode](https://kevinchalet.com/2020/02/18/creating-an-openid-connect-server-proxy-with-openiddict-3-0-s-degraded-mode/)** by [Kévin Chalet](https://github.com/kevinchalet)

**OpenIddict-based projects maintained by third parties**:

- **[ABP Framework OpenIddict module](https://abp.io/)**: full-stack Web application framework for .NET
- **[OpenIddict.AmazonDynamoDB](https://github.com/ganhammar/OpenIddict.AmazonDynamoDB)** by [ganhammar](https://github.com/ganhammar): Amazon DynamoDB stores for OpenIddict
- **[OpenIddict UI](https://github.com/thomasduft/openiddict-ui)** by [Thomas Duft](https://github.com/thomasduft): headless UI for managing client applications and scopes
- **[OrchardCore OpenID module](https://github.com/OrchardCMS/OrchardCore)**: turnkey OpenID Connect server and token validation solution, built with multitenancy in mind
- **[P41.OpenIddict.CouchDB](https://github.com/panoukos41/couchdb-openiddict)** by [Panos Athanasiou](https://github.com/panoukos41): CouchDB stores for OpenIddict
- **[pixel-identity](https://github.com/Nfactor26/pixel-identity)** by [Nishant Singh](https://github.com/Nfactor26): Ready to host OpenID Connect service using OpenIddict and ASP.NET Identity with a Blazor-based UI for managing users, roles, applications and scopes with support for multiple databases.
- **[SharpGrip.OpenIddict.Api](https://github.com/SharpGrip/OpenIddict.Api)** by [SharpGrip](https://github.com/SharpGrip): SharpGrip OpenIddict API is an extension of the OpenIddict library exposing the OpenIddict entities through a RESTful API.

--------------

## Security policy

Security issues and bugs should be reported privately by emailing security@openiddict.com.
You should receive a response within 24 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

--------------

## Support policy

If you need support, please first make sure you're [sponsoring the project](https://github.com/sponsors/kevinchalet).
Depending on the tier you selected, you can open a GitHub ticket or send an email to contact@openiddict.com for private support.
Alternatively, you can also post your question on [Gitter](https://app.gitter.im/#/room/#openiddict_openiddict-core:gitter.im).

**Support is only offered for the latest stable version of OpenIddict**. There are, however, two exceptions to this policy:
  - **ABP Framework users receive patches for OpenIddict for as long as ABP Framework itself is supported by Volosoft**
  (typically a year following the release of a major ABP version), whether they have a commercial ABP license or just use the free packages.

  | OpenIddict branch | ABP Framework branch | End of support date (estimated) |
  |-------------------|----------------------|---------------------------------|
  | 4.x               | 7.x                  | December 19, 2024               |
  | 5.x               | 8.x                  | November 19, 2025               |
  | 6.x (current)     | 9.x                  | Currently supported             |

  - **OpenIddict sponsors are offered extended support depending on the selected sponsorship tier:**
    - $100/month sponsors get full support for the previous version 1 month following the release of a new major version.
    - $250/month sponsors get full support for the previous version 6 months following the release of a new major version.
    - $500/month sponsors get full support for the previous version 12 months following the release of a new major version.
    - $1,000/month sponsors get full support for the previous version 24 months following the release of a new major version.

  | OpenIddict branch | Sponsorship tier       | End of support date |
  |-------------------|------------------------|---------------------|
  | 4.x               | $100/month (or more)   | January 18, 2024    |
  | 4.x               | $250/month (or more)   | June 18, 2024       |
  | 4.x               | $500/month (or more)   | December 18, 2024   |
  | 4.x               | $1,000/month (or more) | December 18, 2025   |
  |                   |                        |                     |
  | 5.x               | $100/month (or more)   | January 17, 2025    |
  | 5.x               | $250/month (or more)   | June 17, 2025       |
  | 5.x               | $500/month (or more)   | December 17, 2025   |
  | 5.x               | $1,000/month (or more) | December 17, 2026   |
  |                   |                        |                     |
  | 6.x (current)     | Any                    | Currently supported |

--------------

## Nightly builds

If you want to try out the latest features and bug fixes, there is a MyGet feed with nightly builds of OpenIddict.
To reference the OpenIddict MyGet feed, **create a `NuGet.config` file** (at the root of your solution):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget" value="https://api.nuget.org/v3/index.json" />
    <add key="openiddict" value="https://www.myget.org/F/openiddict/api/v3/index.json" />
  </packageSources>
</configuration>
```

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/kevinchalet)**. Contributions are welcome and can be submitted using pull requests.

**Special thanks to [our sponsors](https://github.com/sponsors/kevinchalet#sponsors) for their incredible support**:

<a href="https://volosoft.com/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://volosoft.com/assets/logos/volosoft-logo-light.svg">
    <img src="https://volosoft.com/assets/logos/volosoft-logo-dark.svg" width="500px" alt="Volosoft logo" />
  </picture>
</a>

<br />
<br />

<a href="https://www.openiddictcomponents.com/">
  <img src="https://www.openiddictcomponents.com/img/openiddict-components-logo.png" width="400px" alt="OpenIddict Components logo" />
</a>

<br />
<br />

<!-- sponsors --><a href="https://github.com/sebastienros"><img src="https://github.com/sebastienros.png" width="60px" alt="Sébastien Ros" /></a><a href="https://github.com/schmitch"><img src="https://github.com/schmitch.png" width="60px" alt="Schmitt Christian" /></a><a href="https://github.com/cryo75"><img src="https://github.com/cryo75.png" width="60px" alt="" /></a><a href="https://github.com/SebastianStehle"><img src="https://github.com/SebastianStehle.png" width="60px" alt="Sebastian Stehle" /></a><a href="https://github.com/communicatie-cockpit"><img src="https://github.com/communicatie-cockpit.png" width="60px" alt="Communicatie Cockpit" /></a><a href="https://github.com/KeithT"><img src="https://github.com/KeithT.png" width="60px" alt="" /></a><a href="https://github.com/Skrypt"><img src="https://github.com/Skrypt.png" width="60px" alt="Jasmin Savard" /></a><a href="https://github.com/ThomasBjallas"><img src="https://github.com/ThomasBjallas.png" width="60px" alt="Thomas" /></a><a href="https://github.com/feededit"><img src="https://github.com/feededit.png" width="60px" alt="" /></a><a href="https://github.com/jonmartinsson"><img src="https://github.com/jonmartinsson.png" width="60px" alt="" /></a><a href="https://github.com/DigitalOpsDev"><img src="https://github.com/DigitalOpsDev.png" width="60px" alt="DigitalOps Co. Ltd." /></a><a href="https://github.com/EYERIDE-Fleet-Management-System"><img src="https://github.com/EYERIDE-Fleet-Management-System.png" width="60px" alt="EYERIDE Fleet Management System" /></a><a href="https://github.com/hypdeb"><img src="https://github.com/hypdeb.png" width="60px" alt="Julien Debache" /></a><a href="https://github.com/StanlyLife"><img src="https://github.com/StanlyLife.png" width="60px" alt="Stian Håve" /></a><a href="https://github.com/ravindUwU"><img src="https://github.com/ravindUwU.png" width="60px" alt="Ravindu Liyanapathirana" /></a><a href="https://github.com/dlandi"><img src="https://github.com/dlandi.png" width="60px" alt="HieronymusBlaze" /></a><a href="https://github.com/ahanoff"><img src="https://github.com/ahanoff.png" width="60px" alt="Akhan Zhakiyanov" /></a><a href="https://github.com/cbst99"><img src="https://github.com/cbst99.png" width="60px" alt="" /></a><a href="https://github.com/blowdart"><img src="https://github.com/blowdart.png" width="60px" alt="Barry Dorrans" /></a><a href="https://github.com/devqsrl"><img src="https://github.com/devqsrl.png" width="60px" alt="DevQ S.r.l." /></a><a href="https://github.com/dgxhubbard"><img src="https://github.com/dgxhubbard.png" width="60px" alt="" /></a><a href="https://github.com/verdie-g"><img src="https://github.com/verdie-g.png" width="60px" alt="Grégoire" /></a><a href="https://github.com/neil-timmerman"><img src="https://github.com/neil-timmerman.png" width="60px" alt="" /></a><a href="https://github.com/forterro"><img src="https://github.com/forterro.png" width="60px" alt="Forterro" /></a><a href="https://github.com/MarcelMalik"><img src="https://github.com/MarcelMalik.png" width="60px" alt="Marcel" /></a><a href="https://github.com/jwillmer"><img src="https://github.com/jwillmer.png" width="60px" alt="Jens Willmer" /></a><a href="https://github.com/craaash80"><img src="https://github.com/craaash80.png" width="60px" alt="" /></a><a href="https://github.com/BlauhausTechnology"><img src="https://github.com/BlauhausTechnology.png" width="60px" alt="Blauhaus Technology (Pty) Ltd" /></a><a href="https://github.com/trejjam"><img src="https://github.com/trejjam.png" width="60px" alt="Jan Trejbal" /></a><a href="https://github.com/aviationexam"><img src="https://github.com/aviationexam.png" width="60px" alt="Aviationexam s.r.o." /></a><a href="https://github.com/monofor"><img src="https://github.com/monofor.png" width="60px" alt="Monofor" /></a><a href="https://github.com/ratiodata-se"><img src="https://github.com/ratiodata-se.png" width="60px" alt="Ratiodata SE" /></a><a href="https://github.com/DennisvanZetten"><img src="https://github.com/DennisvanZetten.png" width="60px" alt="Dennis van Zetten" /></a><a href="https://github.com/jeroenbai"><img src="https://github.com/jeroenbai.png" width="60px" alt="Jeroen" /></a><a href="https://github.com/Lombiq"><img src="https://github.com/Lombiq.png" width="60px" alt="Lombiq Technologies Ltd." /></a><a href="https://github.com/pureblazor"><img src="https://github.com/pureblazor.png" width="60px" alt="PureBlazor" /></a><a href="https://github.com/HabardiT"><img src="https://github.com/HabardiT.png" width="60px" alt="" /></a><a href="https://github.com/AndrewBabbitt97"><img src="https://github.com/AndrewBabbitt97.png" width="60px" alt="Andrew Babbitt" /></a><a href="https://github.com/softawaregmbh"><img src="https://github.com/softawaregmbh.png" width="60px" alt="softaware gmbh" /></a><a href="https://github.com/SingularSystems"><img src="https://github.com/SingularSystems.png" width="60px" alt="Singular Systems" /></a><a href="https://github.com/SCP-srl"><img src="https://github.com/SCP-srl.png" width="60px" alt="SCP-srl" /></a><a href="https://github.com/realisable"><img src="https://github.com/realisable.png" width="60px" alt="Realisable Software" /></a><a href="https://github.com/dewijones92"><img src="https://github.com/dewijones92.png" width="60px" alt="" /></a><!-- sponsors -->

--------------

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely.
See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
