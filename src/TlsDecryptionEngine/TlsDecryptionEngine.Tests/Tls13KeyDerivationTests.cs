using System;
using System.Security.Cryptography;
using Xunit;
using TlsDecryptionEngine.Kdf;

namespace TlsDecryptionEngine.Tests;

public class Tls13KeyDerivationTests
{
    // These tests use known HKDF vectors (e.g., RFC 5869 Test Case 1)
    [Fact]
    public void HKDF_Extract_And_Expand_Matches_RFC5869_TC1()
    {
        // RFC 5869 Test Case 1:
        // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
        // salt = 0x000102030405060708090a0b0c0d0e0f10111213
        // info = 0xf0f1f2f3f4f5f6f7f8f9
        // L    = 42

        byte[] ikm = KeyLogFileParser.ConvertHexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = KeyLogFileParser.ConvertHexStringToByteArray("000102030405060708090a0b0c");
        byte[] info = KeyLogFileParser.ConvertHexStringToByteArray("f0f1f2f3f4f5f6f7f8f9");
        int L = 42;

        byte[] expectedPrk = KeyLogFileParser.ConvertHexStringToByteArray("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expectedOkm = KeyLogFileParser.ConvertHexStringToByteArray("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        byte[] prk = Tls13KeyDerivation.HKDFExtract(salt, ikm, HashAlgorithmName.SHA256);
        Assert.Equal(expectedPrk, prk);

        byte[] okm = Tls13KeyDerivation.HKDFExpand(prk, info, L, HashAlgorithmName.SHA256);
        Assert.Equal(expectedOkm, okm);
    }
}
