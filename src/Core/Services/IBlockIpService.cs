using System;
using System.Threading.Tasks;

#nullable enable

namespace Bit.Core.Services
{
    public interface IBlockIpService
    {
        Task BlockIpAsync(string ipAddress, bool permanentBlock);
    }
}
