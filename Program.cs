// dotnet add package VaultSharp

using System;
using System.Linq;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods.Token;

public static class Program
{
    // ===== Fill in your own values here =====
    private const string ServerUrl  = "https://vault.mycompany.com:8200"; // server path
    private const string Token      = "hvs.xxxxxxxxxxxxxxxx";             // token
    private const string Namespace  = "my-namespace";                    // namespace
    private const string SecretPath = "kv/myapp/database";               // secret path (incl. mount, e.g. "kv/...")
    private const string SecretKey  = "password";                        // secret key
    // =========================================

    public static async Task Main()
    {
        try
        {
            string value = await GetSecretValueAsync(ServerUrl, Token, Namespace, SecretPath, SecretKey);
            Console.WriteLine($"Retrieved value of '{SecretKey}' ({value.Length} characters).");
            // Use 'value' here, e.g. in a connection string. Never log the value itself.
        }
        catch (VaultApiException ex)
        {
            Console.Error.WriteLine($"Vault error {(int)ex.HttpStatusCode}: {string.Join("; ", ex.ApiErrors ?? Enumerable.Empty<string>())}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }

    public static async Task<string> GetSecretValueAsync(
        string serverUrl, string token, string vaultNamespace, string secretPath, string secretKey)
    {
        var settings = new VaultClientSettings(serverUrl, new TokenAuthMethodInfo(token))
        {
            Namespace = vaultNamespace
        };
        IVaultClient client = new VaultClient(settings);

        // Split the path into the mount point (first segment) and the path within that mount.
        // "kv/myapp/database" -> mount "kv", path "myapp/database".
        // A "data/" segment (as used in the KV v2 API URL) is stripped if present.
        var parts = secretPath.Trim('/').Split('/', 2);
        if (parts.Length < 2)
            throw new ArgumentException("Secret path must include the mount point, e.g. 'kv/myapp/database'.");

        string mountPoint = parts[0];
        string path = parts[1].StartsWith("data/") ? parts[1]["data/".Length..] : parts[1];

        System.Collections.Generic.IDictionary<string, object> data;
        try
        {
            // KV version 2 (most common)
            var secret = await client.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: path, mountPoint: mountPoint);
            data = secret.Data.Data;
        }
        catch (VaultApiException ex) when ((int)ex.HttpStatusCode is 400 or 404)
        {
            // Fall back to KV version 1
            var secret = await client.V1.Secrets.KeyValue.V1.ReadSecretAsync(path: path, mountPoint: mountPoint);
            data = secret.Data;
        }

        if (!data.TryGetValue(secretKey, out var value) || value is null)
            throw new InvalidOperationException(
                $"Key '{secretKey}' not found. Available keys: {string.Join(", ", data.Keys)}");

        return value.ToString()!;
    }
}
