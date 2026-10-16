// dotnet add package VaultSharp

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods.Cert;

public static class Program
{
    // ===== Fill in your own values here =====
    private const string ServerUrl      = "https://vault.mycompany.com:8200"; // server path
    private const string Namespace      = "my-namespace";                     // namespace
    private const string SecretPath     = "kv/myapp/database";                // secret path (incl. mount, e.g. "kv/...")
    private const string SecretKey      = "password";                         // secret key

    // Certificate auth settings
    private const string CertAuthMount  = "cert";  // mount point of the cert auth method in Vault (default "cert")
    private const string CertRoleName   = null;    // optional: name of the cert role in Vault (null = let Vault match)

    // Option A: load the client certificate from a PFX file
    private const string PfxPath        = @"C:\certs\myapp-client.pfx";
    private const string PfxPassword    = "pfx-password";

    // Option B: load the client certificate from the Windows certificate store by thumbprint
    // (set this to a thumbprint to use the store instead of the PFX file)
    private const string CertThumbprint = null;    // e.g. "A1B2C3D4E5F6..."
    // =========================================

    public static async Task Main()
    {
        try
        {
            X509Certificate2 certificate = string.IsNullOrWhiteSpace(CertThumbprint)
                ? LoadCertificateFromFile(PfxPath, PfxPassword)
                : LoadCertificateFromStore(CertThumbprint);

            string value = await GetSecretValueAsync(ServerUrl, Namespace, certificate, SecretPath, SecretKey);
            Console.WriteLine("Retrieved value of '" + SecretKey + "' (" + value.Length + " characters).");
            // Use 'value' here, e.g. in a connection string. Never log the value itself.
        }
        catch (VaultApiException ex)
        {
            string apiErrors = ex.ApiErrors != null ? string.Join("; ", ex.ApiErrors) : ex.Message;
            Console.Error.WriteLine("Vault error " + (int)ex.HttpStatusCode + ": " + apiErrors);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
        }
    }

    public static async Task<string> GetSecretValueAsync(
        string serverUrl, string vaultNamespace, X509Certificate2 certificate, string secretPath, string secretKey)
    {
        // .NET Framework does not always enable TLS 1.2 by default
        ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;

        // VaultSharp attaches the client certificate to the HTTPS connection and logs in
        // via auth/<CertAuthMount>/login, which returns a Vault token for the following calls
        var authMethod = new CertAuthMethodInfo(CertAuthMount, certificate, CertRoleName);

        var settings = new VaultClientSettings(serverUrl, authMethod);
        if (!string.IsNullOrWhiteSpace(vaultNamespace))
            settings.Namespace = vaultNamespace;

        IVaultClient client = new VaultClient(settings);

        // Split the path into the mount point (first segment) and the path within that mount.
        // "kv/myapp/database" -> mount "kv", path "myapp/database".
        // A "data/" segment (as used in the KV v2 API URL) is stripped if present.
        var parts = secretPath.Trim('/').Split(new[] { '/' }, 2);
        if (parts.Length < 2)
            throw new ArgumentException("Secret path must include the mount point, e.g. 'kv/myapp/database'.");

        const string dataPrefix = "data/";
        string mountPoint = parts[0];
        string path = parts[1].StartsWith(dataPrefix) ? parts[1].Substring(dataPrefix.Length) : parts[1];

        IDictionary<string, object> data;
        try
        {
            // KV version 2 (most common)
            var secret = await client.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: path, mountPoint: mountPoint);
            data = secret.Data.Data;
        }
        catch (VaultApiException ex) when ((int)ex.HttpStatusCode == 400 || (int)ex.HttpStatusCode == 404)
        {
            // Fall back to KV version 1
            var secret = await client.V1.Secrets.KeyValue.V1.ReadSecretAsync(path: path, mountPoint: mountPoint);
            data = secret.Data;
        }

        object value;
        if (!data.TryGetValue(secretKey, out value) || value == null)
            throw new InvalidOperationException(
                "Key '" + secretKey + "' not found. Available keys: " + string.Join(", ", data.Keys));

        return value.ToString();
    }

    /// <summary>Loads a client certificate (including private key) from a PFX/P12 file.</summary>
    private static X509Certificate2 LoadCertificateFromFile(string pfxPath, string password)
    {
        var certificate = new X509Certificate2(
            pfxPath,
            password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

        EnsurePrivateKey(certificate);
        return certificate;
    }

    /// <summary>Loads a client certificate from the Windows certificate store by thumbprint.</summary>
    private static X509Certificate2 LoadCertificateFromStore(string thumbprint)
    {
        // Thumbprints copied from the Windows UI often contain spaces or a hidden leading character
        string cleanThumbprint = new string(thumbprint.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();

        // Look in LocalMachine first (services / IIS), then in CurrentUser
        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            var store = new X509Store(StoreName.My, location);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, cleanThumbprint, validOnly: false);
                if (found.Count > 0)
                {
                    EnsurePrivateKey(found[0]);
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

    private static void EnsurePrivateKey(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
            throw new InvalidOperationException(
                "Certificate '" + certificate.Subject + "' has no private key; it cannot be used for client authentication.");

        if (DateTime.Now > certificate.NotAfter)
            throw new InvalidOperationException(
                "Certificate '" + certificate.Subject + "' expired on " + certificate.NotAfter.ToString("yyyy-MM-dd") + ".");
    }
}
