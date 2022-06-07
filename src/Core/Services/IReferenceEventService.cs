using System.Threading.Tasks;
using Bit.Core.Models.Business;

#nullable enable

namespace Bit.Core.Services
{
    public interface IReferenceEventService
    {
        Task RaiseEventAsync(ReferenceEvent referenceEvent);
    }
}
