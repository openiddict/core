﻿using System;
using System.Collections.Generic;
using System.Globalization;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Represents an OpenIddict scope descriptor.
    /// </summary>
    public class OpenIddictScopeDescriptor
    {
        /// <summary>
        /// Gets or sets the description
        /// associated with the scope.
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Gets the localized descriptions associated with the scope.
        /// </summary>
        public Dictionary<CultureInfo, string> Descriptions { get; } = new Dictionary<CultureInfo, string>();

        /// <summary>
        /// Gets or sets the display name
        /// associated with the scope.
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        /// Gets the localized display names associated with the scope.
        /// </summary>
        public Dictionary<CultureInfo, string> DisplayNames { get; } = new Dictionary<CultureInfo, string>();

        /// <summary>
        /// Gets or sets the unique name
        /// associated with the scope.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets the resources associated with the scope.
        /// </summary>
        public HashSet<string> Resources { get; } = new HashSet<string>(StringComparer.Ordinal);
    }
}
