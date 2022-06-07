using System.Threading.Tasks;
using Bit.Core.Context;
using Bit.Core.Entities;
using Bit.Core.Models.Business;

#nullable enable

namespace Bit.Core.Services
{
    public interface ICaptchaValidationService
    {
        string? SiteKey { get; }
        string? SiteKeyResponseKeyName { get; }
        bool RequireCaptchaValidation(ICurrentContext currentContext, User? user = null);
        Task<CaptchaResponse> ValidateCaptchaResponseAsync(string captchResponse, string clientIpAddress,
            User? user = null);
        string GenerateCaptchaBypassToken(User user);
    }
}
