using System;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.CredentialProvider.Voucher
{
    public class VoucherCredentialProvider : IProvideCredentials
    {
        public async Task<TResult> RedeemTokenAsync<TResult>(Uri providerId, string username, string accessToken,
            Func<string, TResult> success, Func<TResult> invalidCredentials, Func<TResult> couldNotConnect)
        {
            var trustedProvider = Utilities.GetTrustedProviderId();
            var trimChars = new char[] { '/' };
            if (String.Compare(providerId.AbsoluteUri.TrimEnd(trimChars), trustedProvider.AbsoluteUri.TrimEnd(trimChars)) != 0)
                return invalidCredentials();

            var userNameId = await Task.FromResult(Guid.Parse(username));

            return Utilities.ValidateToken(accessToken,
                (authId) =>
                {
                    if (authId.CompareTo(userNameId) != 0)
                        return invalidCredentials();
                    return success(authId.ToString());
                },
                () => invalidCredentials(),
                () => invalidCredentials());
        }
    }
}
