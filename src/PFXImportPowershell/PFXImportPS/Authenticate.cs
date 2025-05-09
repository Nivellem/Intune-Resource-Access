// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portionas of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

namespace Microsoft.Management.Powershell.PFXImport
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Identity.Client;

    public class Authenticate
    {
        public const string AuthURI = "login.microsoftonline.com";
        public const string GraphURI = "https://graph.microsoft.com";
        public const string SchemaVersion = "beta";
        public const string AuthTokenKey = "AuthToken";

        public static readonly string ClientId0 = Guid.Empty.ToString();

        private enum CachedTokenApplicationType
        {
            None,
            PublicApplication,
            ConfidentialApplication,
        }

        private static CachedTokenApplicationType cachedTokenApplicationType = CachedTokenApplicationType.None;

        public static string GetClientId(Hashtable modulePrivateData)
        {
            string result = (string)modulePrivateData["ClientId"] ?? Authenticate.ClientId0;
            if (string.Compare(result, Authenticate.ClientId0, StringComparison.OrdinalIgnoreCase) == 0)
            {
                throw new ArgumentException("ClientId from app registration must be supplied in the PowerShell module PrivateData");
            }

            return result;
        }

        public static string GetAuthURI(Hashtable modulePrivateData)
        {
            return (string)modulePrivateData["AuthURI"] ?? Authenticate.AuthURI;
        }

        public static string GetGraphURI(Hashtable modulePrivateData)
        {
            return (string)modulePrivateData["GraphURI"] ?? Authenticate.GraphURI;
        }

        public static string GetSchemaVersion(Hashtable modulePrivateData)
        {
            return (string)modulePrivateData["SchemaVersion"] ?? Authenticate.SchemaVersion;
        }

        private static string GetAuthority(Hashtable modulePrivateData)
        {
            return string.Format("https://{0}/organizations", GetAuthURI(modulePrivateData));
        }

        private static string GetTenantId(Hashtable modulePrivateData)
        {
            string tenantId = (string)modulePrivateData["TenantId"];
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                if (Guid.TryParse(tenantId, out _))
                {
                    return tenantId;
                }
                else
                {
                    throw new ArgumentException("Specified TenantId is not a valid guid");
                }
            }

            return null;
        }

        private static string GetClientSecret(Hashtable modulePrivateData)
        {
            return (string)modulePrivateData["ClientSecret"];
        }

        private static string GetClientCertThumbprint(Hashtable modulePrivateData)
        {
            return (string)modulePrivateData["ClientCertificateThumbprint"];
        }

        private static X509Certificate2 GetClientCertificate(Hashtable modulePrivateData)
        {
            string thumbprint = GetClientCertThumbprint(modulePrivateData);
            if (string.IsNullOrWhiteSpace(thumbprint))
            {
                throw new ArgumentException("ClientCertificateThumbprint must be provided in module PrivateData");
            }

            using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    validOnly: false
                );

                if (certs.Count == 0)
                {
                    throw new ArgumentException($"Certificate with thumbprint {thumbprint} not found in LocalMachine\\My.");
                }

                return certs[0];
            }
        }

        [SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1401:FieldsMustBePrivate", Justification = "Declaring it as a function helps to test a code path.")]
        [SuppressMessage("Microsoft.Usage", "CA2211:NonConstantFieldsShouldNotBeVisible", Justification = "Needs to be public and can't make functions consts")]
        public static Func<AuthenticationResult, bool> AuthTokenIsValid = (authRes) =>
        {
            return authRes != null && authRes.AccessToken != null && authRes.ExpiresOn > DateTimeOffset.UtcNow;
        };

        private static string redirectUri = @"https://login.microsoftonline.com/common/oauth2/nativeclient";
        public static Uri GetRedirectUri(Hashtable modulePrivateData)
        {
            string uri = (string)modulePrivateData["RedirectURI"] ?? redirectUri;
            return new Uri(uri);
        }

        private static string[] GetScopes(Hashtable modulePrivateData)
        {
            return new string[] { $"{GetGraphURI(modulePrivateData)}/.default" };
        }

        private static IPublicClientApplication BuildMSALClientApplications(Hashtable modulePrivateData)
        {
            return PublicClientApplicationBuilder.Create(GetClientId(modulePrivateData))
                .WithCacheOptions(CacheOptions.EnableSharedCacheOptions)
                .WithAuthority(GetAuthority(modulePrivateData))
                .WithRedirectUri(GetRedirectUri(modulePrivateData).ToString())
                .Build();
        }

        private static IConfidentialClientApplication BuildMSALConfidentialClientApplication(Hashtable modulePrivateData)
        {
            ConfidentialClientApplicationBuilder builder = ConfidentialClientApplicationBuilder.Create(GetClientId(modulePrivateData))
                .WithAuthority(GetAuthority(modulePrivateData))
                .WithRedirectUri(GetRedirectUri(modulePrivateData).ToString())
                .WithTenantId(GetTenantId(modulePrivateData));

            string secret = GetClientSecret(modulePrivateData);
            string thumbprint = GetClientCertThumbprint(modulePrivateData);

            if (!string.IsNullOrWhiteSpace(secret))
            {
                builder = builder.WithClientSecret(secret);
            }
            else if (!string.IsNullOrWhiteSpace(thumbprint))
            {
                X509Certificate2 cert = GetClientCertificate(modulePrivateData);
                builder = builder.WithCertificate(cert);
            }
            else
            {
                throw new ArgumentException("Either ClientSecret or ClientCertificateThumbprint must be provided.");
            }

            return builder.Build();
        }

        public static AuthenticationResult GetAuthToken(string user, SecureString password, Hashtable modulePrivateData)
        {
            if (!string.IsNullOrWhiteSpace(user))
            {
                IPublicClientApplication app = BuildMSALClientApplications(modulePrivateData);
                AuthenticationResult result;

                try
                {
                    if (password == null)
                    {
                        result = app.AcquireTokenInteractive(GetScopes(modulePrivateData))
                            .WithLoginHint(user)
                            .ExecuteAsync().Result;
                    }
                    else
                    {
                        result = app.AcquireTokenByUsernamePassword(GetScopes(modulePrivateData), user, password)
                            .ExecuteAsync().Result;
                    }
                }
                catch (AggregateException ex)
                {
                    throw ex.InnerException;
                }

                cachedTokenApplicationType = CachedTokenApplicationType.PublicApplication;
                return result;
            }
            else
            {
                AuthenticationResult result;

                try
                {
                    IConfidentialClientApplication app = BuildMSALConfidentialClientApplication(modulePrivateData);
                    result = app.AcquireTokenForClient(GetScopes(modulePrivateData))
                        .WithAuthority(string.Format("https://{0}", GetAuthURI(modulePrivateData)), GetTenantId(modulePrivateData))
                        .ExecuteAsync().Result;
                }
                catch (AggregateException ex)
                {
                    throw ex.InnerException;
                }

                cachedTokenApplicationType = CachedTokenApplicationType.ConfidentialApplication;
                return result;
            }
        }

        public static AuthenticationResult GetAuthToken(Hashtable modulePrivateData)
        {
            if (cachedTokenApplicationType == CachedTokenApplicationType.PublicApplication)
            {
                IPublicClientApplication app = BuildMSALClientApplications(modulePrivateData);
                List<IAccount> accounts = new List<IAccount>(app.GetAccountsAsync().Result);

                if (accounts.Count < 1)
                {
                    throw new ArgumentException("No token cached. First call Set-IntuneAuthenticationToken");
                }

                try
                {
                    return app.AcquireTokenSilent(GetScopes(modulePrivateData), accounts[0])
                        .ExecuteAsync().Result;
                }
                catch (AggregateException ex)
                {
                    throw ex.InnerException;
                }
            }
            else if (cachedTokenApplicationType == CachedTokenApplicationType.ConfidentialApplication)
            {
                try
                {
                    IConfidentialClientApplication app = BuildMSALConfidentialClientApplication(modulePrivateData);
                    return app.AcquireTokenForClient(GetScopes(modulePrivateData))
                        .WithAuthority(string.Format("https://{0}", GetAuthURI(modulePrivateData)), GetTenantId(modulePrivateData))
                        .ExecuteAsync().Result;
                }
                catch (AggregateException ex)
                {
                    throw ex.InnerException;
                }
            }
            else
            {
                throw new ArgumentException("No token cached. First call Set-IntuneAuthenticationToken");
            }
        }

        public static void ClearTokenCache(Hashtable modulePrivateData)
        {
            IPublicClientApplication app = BuildMSALClientApplications(modulePrivateData);
            List<IAccount> accounts = new List<IAccount>(app.GetAccountsAsync().Result);

            while (accounts.Count > 0)
            {
                app.RemoveAsync(accounts[0]).Wait();
                accounts = new List<IAccount>(app.GetAccountsAsync().Result);
            }

            cachedTokenApplicationType = CachedTokenApplicationType.None;
        }
    }
}

