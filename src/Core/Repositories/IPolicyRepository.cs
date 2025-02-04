﻿using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Bit.Core.Entities;
using Bit.Core.Enums;
using Bit.Core.Models.Data.Organizations.Policies;

namespace Bit.Core.Repositories
{
    public interface IPolicyRepository : IRepository<Policy, Guid>
    {
        Task<Policy> GetByOrganizationIdTypeAsync(Guid organizationId, PolicyType type);
        Task<ICollection<Policy>> GetManyByOrganizationIdAsync(Guid organizationId);
        Task<ICollection<Policy>> GetManyByUserIdAsync(Guid userId);
        Task<ICollection<Policy>> GetManyByTypeApplicableToUserIdAsync(Guid userId, PolicyType policyType,
            OrganizationUserStatusType minStatus = OrganizationUserStatusType.Accepted);
        Task<int> GetCountByTypeApplicableToUserIdAsync(Guid userId, PolicyType policyType,
            OrganizationUserStatusType minStatus = OrganizationUserStatusType.Accepted);
    }
}
