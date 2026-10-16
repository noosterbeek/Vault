// OutSystems 11 extension (Integration Studio) - HashiCorp Vault access via VaultSharp
// Authentication: TLS client certificate (Vault "cert" auth method)
//
// Integration Studio setup:
//   Extension name : VaultExtension
//   Action         : GetSecretValue
//     Input  ServerUrl      (Text)         e.g. "https://vault.mycompany.com:8200"
//     Input  Namespace      (Text)         may be empty
//     Input  CertAuthMount  (Text)         mount point of the cert auth method; empty = "cert"
//     Input  CertRoleName   (Text)         optional cert role name in Vault; empty = let Vault match
//     Input  CertThumbprint (Text)         option A: certificate from the Windows store (LocalMachine\My)
//     Input  CertificatePfx (Binary Data)  option B: PFX/P12 file content (used when CertThumbprint is empty)
//     Input  PfxPassword    (Text)         password for option B
//     Input  SecretPath     (Text)         e.g. "kv/myapp/database" (mount point included)
//     Input  SecretKey      (Text)
//     Output Value          (Text)
//     Output Success        (Boolean)
//     Output ErrorMessage   (Text)
//
// After defining the action, click "Edit Source Code .NET" and replace the generated
// class with the code below. Add VaultSharp.dll (and its dependencies) to the project
// references and as Resources in Integration Studio (Deploy Action: "Copy to Binaries Directory").

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods.Cert;

namespace OutSystems.NssVaultExtension
{
    public class CssVaultExtension : IssVaultExtension
    {
        /// <summary>
        /// Reads a single key from a secret in HashiCorp Vault (KV v2, with fallback to KV v1),
        /// authenticating with a TLS client certificate.
        /// </summary>
        public void MssGetSecretValue(
            string ssServerUrl,
            string ssNamespace,
            string ssCertAuthMount,
            string ssCertRoleName,
            string ssCertThumbprint,
            byte[] ssCertificatePfx,
            string ssPfxPassword,
            string ssSecretPath,
            string ssSecretKey,
            out string ssValue,
            out bool ssSuccess,
            out string ssErrorMessage)
        {
            ssValue = "";
            ssSuccess = false;
            ssErrorMessage = "";

            X509Certificate2 certificate = null;
            try
            {
                // .NET Framework does not always enable TLS 1.2 by default
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;

                certificate = !string.IsNullOrWhiteSpace(ssCertThumbprint)
                    ? LoadCertificateFromStore(ssCertThumbprint)
                    : LoadCertificateFromBytes(ssCertificatePfx, ssPfxPassword);

                string authMount = string.IsNullOrWhiteSpace(ssCertAuthMount) ? "cert" : ssCertAuthMount;
                string roleName = string.IsNullOrWhiteSpace(ssCertRoleName) ? null : ssCertRoleName;

                // Run the async call on the thread pool to avoid deadlocks with the
                // ASP.NET synchronization context, then block for the result
                X509Certificate2 cert = certificate;
                ssValue = Task.Run(() => GetSecretValueAsync(
                        ssServerUrl, ssNamespace, authMount, roleName, cert, ssSecretPath, ssSecretKey))
                    .GetAwaiter()
                    .GetResult();

                ssSuccess = true;
            }
            catch (VaultApiException ex)
            {
                string apiErrors = ex.ApiErrors != null ? string.Join("; ", ex.ApiErrors) : ex.Message;
                ssErrorMessage = "Vault error " + (int)ex.HttpStatusCode + ": " + apiErrors;
            }
            catch (Exception ex)
            {
                ssErrorMessage = "Error: " + ex.Message;
            }
            finally
            {
                // Releases the certificate handle (and, for option B, the temporary private key)
                if (certificate != null)
                    certificate.Dispose();
            }
        }

        private static async Task<string> GetSecretValueAsync(
            string serverUrl, string vaultNamespace, string certAuthMount, string certRoleName,
            X509Certificate2 certificate, string secretPath, string secretKey)
        {
            if (string.IsNullOrWhiteSpace(serverUrl)) throw new ArgumentException("ServerUrl is required.");
            if (string.IsNullOrWhiteSpace(secretPath)) throw new ArgumentException("SecretPath is required.");
            if (string.IsNullOrWhiteSpace(secretKey)) throw new ArgumentException("SecretKey is required.");

            // VaultSharp attaches the client certificate to the HTTPS connection and logs in
            // via auth/<certAuthMount>/login, which returns a Vault token for the following calls
            var authMethod = new CertAuthMethodInfo(certAuthMount, certificate, certRoleName);

            var settings = new VaultClientSettings(serverUrl, authMethod);
            if (!string.IsNullOrWhiteSpace(vaultNamespace))
                settings.Namespace = vaultNamespace;

            IVaultClient client = new VaultClient(settings);

            // Split the path into the mount point (first segment) and the path within that mount.
            // "kv/myapp/database" -> mount "kv", path "myapp/database".
            // A "data/" segment (as used in the KV v2 API URL) is stripped if present.
            var parts = secretPath.Trim('/').Split(new[] { '/' }, 2);
            if (parts.Length < 2)
                throw new ArgumentException("SecretPath must include the mount point, e.g. 'kv/myapp/database'.");

            const string dataPrefix = "data/";
            string mountPoint = parts[0];
            string path = parts[1].StartsWith(dataPrefix) ? parts[1].Substring(dataPrefix.Length) : parts[1];

            IDictionary<string, object> data;
            try
            {
                // KV version 2 (most common)
                var secret = await client.V1.Secrets.KeyValue.V2
                    .ReadSecretAsync(path: path, mountPoint: mountPoint)
                    .ConfigureAwait(false);
                data = secret.Data.Data;
            }
            catch (VaultApiException ex) when ((int)ex.HttpStatusCode == 400 || (int)ex.HttpStatusCode == 404)
            {
                // Fall back to KV version 1
                var secret = await client.V1.Secrets.KeyValue.V1
                    .ReadSecretAsync(path: path, mountPoint: mountPoint)
                    .ConfigureAwait(false);
                data = secret.Data;
            }

            object value;
            if (!data.TryGetValue(secretKey, out value) || value == null)
                throw new InvalidOperationException(
                    "Key '" + secretKey + "' not found. Available keys: " + string.Join(", ", data.Keys));

            return value.ToString();
        }

        /// <summary>Loads a client certificate (including private key) from PFX/P12 bytes.</summary>
        private static X509Certificate2 LoadCertificateFromBytes(byte[] pfxBytes, string password)
        {
            if (pfxBytes == null || pfxBytes.Length == 0)
                throw new ArgumentException("Provide either CertThumbprint or CertificatePfx.");

            // MachineKeySet: IIS app pool identities often have no loaded user profile.
            // No PersistKeySet: the temporary key is removed again when the certificate is disposed.
            var certificate = new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.MachineKeySet);

            EnsureUsable(certificate);
            return certificate;
        }

        /// <summary>Loads a client certificate from the Windows certificate store by thumbprint.</summary>
        private static X509Certificate2 LoadCertificateFromStore(string thumbprint)
        {
            // Thumbprints copied from the Windows UI often contain spaces or a hidden leading character
            string cleanThumbprint = new string(thumbprint.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();

            // OutSystems runs under IIS, so LocalMachine is checked first, then CurrentUser
            foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
            {
                var store = new X509Store(StoreName.My, location);
                try
                {
                    store.Open(OpenFlags.ReadOnly);
                    var found = store.Certificates.Find(X509FindType.FindByThumbprint, cleanThumbprint, false);
                    if (found.Count > 0)
                    {
                        EnsureUsable(found[0]);
                        return found[0];
                    }
                }
                finally
                {
                    store.Close();
                }
            }

            throw new InvalidOperationException("Certificate with thumbprint '" + cleanThumbprint + "' not found.");
        }

        private static void EnsureUsable(X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
                throw new InvalidOperationException(
                    "Certificate '" + certificate.Subject + "' has no private key; it cannot be used for client authentication.");

            if (DateTime.Now > certificate.NotAfter)
                throw new InvalidOperationException(
                    "Certificate '" + certificate.Subject + "' expired on " + certificate.NotAfter.ToString("yyyy-MM-dd") + ".");
        }
    }
}
