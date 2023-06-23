package com.dsp.automation;

import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class EncryptionUtilTest {

    private String projectId = "sawitprorelease1";

    private String locationId = "asia";

    private String keyRingId = "flo-trial-key-ring";

    private String keyId = "flo-trial-key";

    private String keyVersionId = "1";

    @Test
    public void encryptTest() throws Exception {
        String encryptedPhoneNumber = encryptAsymmetric("081574905117");
        String encryptedPin = encryptAsymmetric("111111");

        System.out.println("Encrypted PhoneNumber: " + encryptedPhoneNumber);
        System.out.println("Encrypted PIN: " + encryptedPin);

        Assertions.assertTrue(true);
    }

    public PrivateKey generateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        //keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = (PublicKey) kp.getPublic();
        PrivateKey privateKey = (PrivateKey) kp.getPrivate();
        return privateKey;
    }

    public PublicKey getAsymmetricPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            // Build the key version name from the project, location, key ring, key,
            // and key version.
            CryptoKeyVersionName keyVersionName =
                    CryptoKeyVersionName.of(projectId, locationId, keyRingId, keyId, keyVersionId);

            // Get the public key.
            com.google.cloud.kms.v1.PublicKey publicKey = client.getPublicKey(keyVersionName);

            byte[] derKey = convertPemToDer(publicKey.getPem());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);

            java.security.PublicKey rsaKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

            return rsaKey;
        }
    }

    public String decryptAsymmetric(byte[] ciphertext) throws IOException {
        // TODO(developer): Replace these variables before running the sample.

        return decryptAsymmetric(projectId, locationId, keyRingId, keyId, keyVersionId, ciphertext);
    }

    public String decryptAsymmetric(String ciphertextString) throws IOException {
        // TODO(developer): Replace these variables before running the sample.

        byte[] ciphertext = decodeStringToBinaryMime(ciphertextString);

        return decryptAsymmetric(projectId, locationId, keyRingId, keyId, keyVersionId, ciphertext);
    }

    // Decrypt data that was encrypted using the public key component of the given
    // key version.
    public String decryptAsymmetric(
            String projectId,
            String locationId,
            String keyRingId,
            String keyId,
            String keyVersionId,
            byte[] ciphertext)
            throws IOException {
        // Initialize client that will be used to send requests. This client only
        // needs to be created once, and can be reused for multiple requests. After
        // completing all of your requests, call the "close" method on the client to
        // safely clean up any remaining background resources.
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            System.out.println("[FLO] encrypted text in String: "+ encodeBinaryToString(ciphertext));
            System.out.println("[FLO] encrypted text in String without padding: "+ encodeBinaryUrlWithoutPaddingToString(ciphertext));

            // Build the key version name from the project, location, key ring, key,
            // and key version.
            CryptoKeyVersionName keyVersionName =
                    CryptoKeyVersionName.of(projectId, locationId, keyRingId, keyId, keyVersionId);
            System.out.println("[FLO] already Build the key version name from the project, location, key ring, key");

            ByteString cipherTextByteString = ByteString.copyFrom(ciphertext);
            System.out.println("[FLO] the size of the original cipertext in bytes is: " + ciphertext.length);
            System.out.println("[FLO] the size of the cipertext in bytes is: " + cipherTextByteString.size());

            // Decrypt the ciphertext.
            AsymmetricDecryptResponse response =
                    client.asymmetricDecrypt(keyVersionName, cipherTextByteString);
            //System.out.printf("Plaintext: %s%n", response.getPlaintext().toStringUtf8());
            System.out.println("Plaintext: " + response.getPlaintext().toStringUtf8());
            return response.getPlaintext().toStringUtf8();
        }
    }

    public String encryptAsymmetric(String plaintext) throws IOException, GeneralSecurityException {
        System.out.println("1st encryptAsymmetric method is called");
        return encodeBinaryToString(getCipherTextFromEncryptAsymmetric(plaintext));
    }

    // Encrypt data that was encrypted using the public key component of the given
    // key version.
    public byte[] getCipherTextFromEncryptAsymmetric(String plaintext) throws IOException, GeneralSecurityException {
        System.out.println("2nd encryptAsymmetric meth/od is called");
        // Initialize client that will be used to send requests. This client only
        // needs to be created once, and can be reused for multiple requests. After
        // completing all of your requests, call the "close" method on the client to
        // safely clean up any remaining background resources.
        PublicKey rsaKey = getAsymmetricPublicKey();

        // (in GCP example) Encrypt plaintext for the 'RSA_DECRYPT_OAEP_2048_SHA256' key.
        // (in our case) Encrypt plaintext for the 'RSA_DECRYPT_OAEP_3072_SHA256' key.
        // For other key algorithms:
        // https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParams =
                new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, rsaKey, oaepParams);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        System.out.println("the encrypted phone number ciphertext length is: "+ciphertext.length);
        System.out.println("the encrypted phone number in base64 string is: "+encodeBinaryToString(ciphertext));
        System.out.printf("Ciphertext: %s%n", ciphertext);

        return ciphertext;
    }

    // Converts a base64-encoded PEM certificate like the one returned from Cloud
    // KMS into a DER formatted certificate for use with the Java APIs.
    private byte[] convertPemToDer(String pem) {
        BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
        String encoded =
                bufferedReader
                        .lines()
                        .filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
                        .collect(Collectors.joining());
        return Base64.getDecoder().decode(encoded);
    }

    public static String encodeBinaryToString(byte[] object) {
        return new String(Base64.getEncoder().encode(object));
    }

    public static String encodeBinaryUrlWithoutPaddingToString(byte[] object) {
        return new String(Base64.getUrlEncoder().withoutPadding().encode(object));
    }

    public static byte[] decodeStringToBinary(String object) {
        return Base64.getDecoder().decode(object);
    }

    public static byte[] decodeStringToBinaryUrl(String object) {
        return Base64.getUrlDecoder().decode(object);
    }

    public static byte[] decodeStringToBinaryMime(String object) {
        return Base64.getMimeDecoder().decode(object);
    }
}
