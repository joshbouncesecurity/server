using System;
using System.Collections.Generic;
using Bit.Core.Enums;

#nullable enable

namespace Bit.Core.Models
{
    public interface ITwoFactorProvidersUser
    {
        string? TwoFactorProviders { get; }
        Dictionary<TwoFactorProviderType, TwoFactorProvider>? GetTwoFactorProviders();
        Guid? GetUserId();
        bool GetPremium();
    }
}
