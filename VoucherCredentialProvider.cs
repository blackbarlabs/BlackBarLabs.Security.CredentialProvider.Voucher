using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.CredentialProvider.Voucher
{
    public class VoucherCredentialProvider : IProvideCredentials
    {
        public async Task<string> RedeemTokenAsync(Uri providerId, string username, string accessToken)
        {
            var trustedProvider = Utilities.GetTrustedProviderId();
            var trimChars = new char[] { '/' };
            if (String.Compare(providerId.AbsoluteUri.TrimEnd(trimChars), trustedProvider.AbsoluteUri.TrimEnd(trimChars)) != 0)
                return default(string);

            var userNameId = await Task.FromResult(Guid.Parse(username));

            return Utilities.ValidateToken(accessToken,
                (authId) =>
                {
                    if (authId.CompareTo(userNameId) != 0)
                        return default(string);
                    return authId.ToString();
                },
                () => default(string),
                () => default(string));
        }
    }
}
