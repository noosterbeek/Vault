// OutSystems 11 extension (Integration Studio) - HashiCorp Vault access via VaultSharp
//
// Integration Studio setup:
//   Extension name : VaultExtension
//   Action         : GetSecretValue
//     Input  ServerUrl    (Text)
//     Input  Token        (Text)
//     Input  Namespace    (Text)
//     Input  SecretPath   (Text)   e.g. "kv/myapp/database" (mount point included)
//     Input  SecretKey    (Text)
//     Output Value        (Text)
//     Output Success      (Boolean)
//     Output ErrorMessage (Text)
//
// After defining the action, click "Edit Source Code .NET" and replace the generated
// method body with the code below. Add VaultSharp.dll (and its dependencies) to the
// project references and as Resources in Integration Studio (Deploy Action: "Copy to Binaries Directory").

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods.Token;

namespace OutSystems.NssVaultExtension
{
    public class CssVaultExtension : IssVaultExtension
    {
        /// <summary>
        /// Reads a single key from a secret in HashiCorp Vault (KV v2, with fallback to KV v1).
        /// </summary>
        public void MssGetSecretValue(
            string ssServerUrl,
            string ssToken,
            string ssNamespace,
            string ssSecretPath,
            string ssSecretKey,
            out string ssValue,
            out bool ssSuccess,
            out string ssErrorMessage)
        {
            ssValue = "";
            ssSuccess = false;
            ssErrorMessage = "";

            try
            {
                // .NET Framework does not always enable TLS 1.2 by default
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;

                // Run the async call on the thread pool to avoid deadlocks with the
                // ASP.NET synchronization context, then block for the result
                ssValue = Task.Run(() => GetSecretValueAsync(
                        ssServerUrl, ssToken, ssNamespace, ssSecretPath, ssSecretKey))
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
        }

        private static async Task<string> GetSecretValueAsync(
            string serverUrl, string token, string vaultNamespace, string secretPath, string secretKey)
        {
            if (string.IsNullOrWhiteSpace(serverUrl)) throw new ArgumentException("ServerUrl is required.");
            if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("Token is required.");
            if (string.IsNullOrWhiteSpace(secretPath)) throw new ArgumentException("SecretPath is required.");
            if (string.IsNullOrWhiteSpace(secretKey)) throw new ArgumentException("SecretKey is required.");

            var settings = new VaultClientSettings(serverUrl, new TokenAuthMethodInfo(token));
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
    }
}
