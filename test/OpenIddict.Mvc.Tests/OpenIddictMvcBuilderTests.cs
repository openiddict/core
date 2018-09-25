﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Mvc.Tests
{
    public class OpenIddictMvcBuilderTests
    {
        [Fact]
        public void Constructor_ThrowsAnExceptionForNullServices()
        {
            // Arrange
            var services = (IServiceCollection) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictMvcBuilder(services));

            Assert.Equal("services", exception.ParamName);
        }

        [Fact]
        public void Configure_OptionsAreCorrectlyAmended()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.Configure(configuration => configuration.DisableBindingExceptions = true);

            var options = GetOptions(services);

            // Assert
            Assert.True(options.DisableBindingExceptions);
        }

        private static IServiceCollection CreateServices()
            => new ServiceCollection().AddOptions();

        private static OpenIddictMvcBuilder CreateBuilder(IServiceCollection services)
            => new OpenIddictMvcBuilder(services);

        private static OpenIddictMvcOptions GetOptions(IServiceCollection services)
        {
            var provider = services.BuildServiceProvider();
            return provider.GetRequiredService<IOptions<OpenIddictMvcOptions>>().Value;
        }
    }
}
