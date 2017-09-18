﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;

namespace OpenIddict.Models
{
    /// <summary>
    /// Represents an OpenIddict authorization.
    /// </summary>
    public class OpenIddictAuthorization : OpenIddictAuthorization<string, OpenIddictApplication, OpenIddictToken>
    {
        public OpenIddictAuthorization()
        {
            // Generate a new string identifier.
            AuthorizationId = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents an OpenIddict authorization.
    /// </summary>
    public class OpenIddictAuthorization<TKey> : OpenIddictAuthorization<TKey, OpenIddictApplication<TKey>, OpenIddictToken<TKey>>
        where TKey : IEquatable<TKey>
    { }

    /// <summary>
    /// Represents an OpenIddict authorization.
    /// </summary>
    public class OpenIddictAuthorization<TKey, TApplication, TToken> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Gets or sets the application associated with the current authorization.
        /// </summary>
        public virtual TApplication Application { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current application.
        /// </summary>
        public virtual TKey ApplicationId { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier
        /// associated with the current authorization.
        /// </summary>
        public virtual TKey AuthorizationId { get; set; }

        /// <summary>
        /// Gets or sets the space-delimited scopes
        /// associated with the current authorization.
        /// </summary>
        public virtual string Scope { get; set; }

        /// <summary>
        /// Gets or sets the status of the current authorization.
        /// </summary>
        public virtual string Status { get; set; } = "valid";

        /// <summary>
        /// Gets or sets the subject associated with the current authorization.
        /// </summary>
        public virtual string Subject { get; set; }

        /// <summary>
        /// Gets or sets the list of tokens
        /// associated with the current authorization.
        /// </summary>
        public virtual IList<TToken> Tokens { get; } = new List<TToken>();
    }
}
