﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict.Models
{
    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    public class OpenIddictToken : OpenIddictToken<string, OpenIddictApplication, OpenIddictAuthorization>
    {
        public OpenIddictToken()
        {
            // Generate a new string identifier.
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    public class OpenIddictToken<TKey> : OpenIddictToken<TKey, OpenIddictApplication<TKey>, OpenIddictAuthorization<TKey>>
        where TKey : IEquatable<TKey>
    {
    }

    /// <summary>
    /// Represents an OpenIddict token.
    /// </summary>
    public class OpenIddictToken<TKey, TApplication, TAuthorization> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Gets or sets the application associated with the current token.
        /// </summary>
        public virtual TApplication Application { get; set; }

        /// <summary>
        /// Gets or sets the authorization associated with the current token.
        /// </summary>
        public virtual TAuthorization Authorization { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current token.
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Gets or sets the subject associated with the current token.
        /// </summary>
        public virtual string Subject { get; set; }

        /// <summary>
        /// Gets or sets the type of the current token.
        /// </summary>
        public virtual string Type { get; set; }

        /// <summary>
        /// Gets or sets the datetime that the token was issued.  
        /// </summary>
        public virtual DateTimeOffset? IssuedUtc { get; set; }

        /// <summary>
        /// Gets or sets the datetime that the token expires.
        /// </summary>
        public virtual DateTimeOffset? ExpiresUtc { get; set; }
    }
}
