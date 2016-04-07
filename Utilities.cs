using System;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;

namespace BlackBarLabs.Security.CredentialProvider.Voucher
{
    public static class Utilities
    {
        public static Uri GetTrustedProviderId()
        {
            var trustedVoucherProviderString = ConfigurationManager.AppSettings["BlackbarLabs.Security.CredentialProvider.Voucher.provider"];
            var trustedVoucherProviderId = new Uri(trustedVoucherProviderString);
            return trustedVoucherProviderId;
        }
    }
}
