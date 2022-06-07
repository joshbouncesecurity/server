using System.Threading.Tasks;
using Bit.Core.Models.Business;

#nullable enable

namespace Bit.Core.Services
{
    public class NoopReferenceEventService : IReferenceEventService
    {
        public Task RaiseEventAsync(ReferenceEvent referenceEvent)
        {
            return Task.CompletedTask;
        }
    }
}
