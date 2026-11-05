// =============================================================================
// OutSystems 11 – Integration Studio extension "CertificateReader"
// Target: .NET Framework 4.7.2 or later. No external NuGet packages required.
// =============================================================================
//
// Reads the validity period of an X.509 certificate (DER .cer/.crt, PEM, or
// PFX without password). All dates are returned in UTC.
//
// -----------------------------------------------------------------------------
// WHAT TO CREATE IN INTEGRATION STUDIO
// -----------------------------------------------------------------------------
// Use exactly the names below: this code relies on the identifiers that
// Integration Studio generates from them (RCCertificateInfoRecord,
// ssSTCertificateInfo, ssNotBefore, ssNotAfter, ...).
//
// 1. File > New Extension
//      Name:     CertificateReader
//      Language: C#
//
// 2. Structure "CertificateInfo"  (Structures > right-click > Add Structure)
//
//      Attribute                   Data Type   Description
//      --------------------------  ----------  -----------------------------------------
//      NotBefore                   Date Time   Valid from (UTC)
//      NotAfter                    Date Time   Valid until / expiration date (UTC)
//      IsExpired                   Boolean     NotAfter is in the past
//      IsNotYetValid               Boolean     NotBefore is in the future
//      IsWithinValidityPeriod      Boolean     Now is between NotBefore and NotAfter
//
// 3. Action "GetCertificateInfo"  (Actions > right-click > Add Action)
//
//      Parameter                   Direction   Data Type
//      --------------------------  ----------  ---------------------------------
//      CertificateData             Input       Binary Data   (Is Mandatory = Yes)
//      Info                        Output      CertificateInfo Record
//
// 4. Click "Edit Source Code .NET" and replace the generated CertificateReader.cs
//    with this file. Build in Visual Studio.
//
// 5. Back in Integration Studio: 1-Click Publish.
//
// 6. In Service Studio: Manage Dependencies > CertificateReader > GetCertificateInfo.
//    Example: GetCertificateInfo.Info.NotAfter, GetCertificateInfo.Info.IsExpired
//
// Notes
//  - A PEM certificate as text can be converted with TextToBinaryData()
//    (BinaryData extension) before calling the action.
//  - Invalid or empty input raises an exception; catch it with an Exception Handler.
// =============================================================================

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace OutSystems.NssCertificateReader
{
    public class CssCertificateReader : IssCertificateReader
    {
        /// <summary>Returns the validity period of a certificate.</summary>
        /// <param name="ssCertificateData">Binary content of the certificate file (DER, PEM or PFX without password).</param>
        /// <param name="ssInfo">Validity information of the certificate.</param>
        public void MssGetCertificateInfo(byte[] ssCertificateData, out RCCertificateInfoRecord ssInfo)
        {
            ssInfo = new RCCertificateInfoRecord(null);

            using (X509Certificate2 cert = LoadFromBinary(ssCertificateData))
            {
                DateTime notBefore = cert.NotBefore.ToUniversalTime();
                DateTime notAfter = cert.NotAfter.ToUniversalTime();
                DateTime now = DateTime.UtcNow;

                ssInfo.ssSTCertificateInfo.ssNotBefore = notBefore;
                ssInfo.ssSTCertificateInfo.ssNotAfter = notAfter;
                ssInfo.ssSTCertificateInfo.ssIsExpired = notAfter < now;
                ssInfo.ssSTCertificateInfo.ssIsNotYetValid = notBefore > now;
                ssInfo.ssSTCertificateInfo.ssIsWithinValidityPeriod = notBefore <= now && now <= notAfter;
            }
        }

        // ---------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------

        /// <summary>Loads a certificate from binary data. Detects PEM text; otherwise treats it as DER or PFX.</summary>
        private static X509Certificate2 LoadFromBinary(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("CertificateData is empty.");

            try
            {
                // Quick check on the first bytes to see whether this is a PEM text file.
                string head = Encoding.ASCII.GetString(data, 0, Math.Min(data.Length, 4096));
                if (head.Contains("-----BEGIN CERTIFICATE-----"))
                    return new X509Certificate2(PemToDer(Encoding.UTF8.GetString(data)));

                return new X509Certificate2(data);
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException("CertificateData is not a valid certificate: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Converts PEM text to DER bytes.
        /// .NET Framework has no X509Certificate2.CreateFromPem, so the headers are stripped manually.
        /// If the text contains a chain, only the first certificate is used.
        /// </summary>
        private static byte[] PemToDer(string pem)
        {
            Match m = Regex.Match(pem,
                "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                RegexOptions.Singleline);

            if (!m.Success)
                throw new ArgumentException("Invalid PEM: no certificate block found.");

            string base64 = Regex.Replace(m.Groups[1].Value, @"\s+", "");

            try
            {
                return Convert.FromBase64String(base64);
            }
            catch (FormatException)
            {
                throw new ArgumentException("Invalid PEM: certificate block is not valid Base64.");
            }
        }
    }
}
