using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Bit.Core.Entities;
using Bit.Core.Entities.Provider;
using Bit.Core.Models.Business;
using Bit.Core.Models.Business.Provider;

#nullable enable

namespace Bit.Core.Services
{
    public class NoopProviderService : IProviderService
    {
        [DoesNotReturn]
        public Task CreateAsync(string ownerEmail) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task<Provider> CompleteSetupAsync(Provider provider, Guid ownerUserId, string token, string key) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task UpdateAsync(Provider provider, bool updateBilling = false) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task<List<ProviderUser>> InviteUserAsync(ProviderUserInvite<string> invite) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task<List<Tuple<ProviderUser, string>>> ResendInvitesAsync(ProviderUserInvite<Guid> invite) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task<ProviderUser> AcceptUserAsync(Guid providerUserId, User user, string token) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task<List<Tuple<ProviderUser, string>>> ConfirmUsersAsync(Guid providerId, Dictionary<Guid, string> keys, Guid confirmingUserId) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task SaveUserAsync(ProviderUser user, Guid savingUserId) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task<List<Tuple<ProviderUser, string>>> DeleteUsersAsync(Guid providerId, IEnumerable<Guid> providerUserIds, Guid deletingUserId) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task AddOrganization(Guid providerId, Guid organizationId, Guid addingUserId, string key) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task<ProviderOrganization> CreateOrganizationAsync(Guid providerId, OrganizationSignup organizationSignup, string clientOwnerEmail, User user) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task RemoveOrganizationAsync(Guid providerId, Guid providerOrganizationId, Guid removingUserId) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task LogProviderAccessToOrganizationAsync(Guid organizationId) => throw new NotImplementedException();

        [DoesNotReturn]
        public Task ResendProviderSetupInviteEmailAsync(Guid providerId, Guid userId) => throw new NotImplementedException();
    }
}
