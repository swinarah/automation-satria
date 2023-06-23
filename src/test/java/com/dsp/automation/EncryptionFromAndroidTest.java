package com.dsp.automation;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptionFromAndroidTest {

    @Test
    public void generateEncryptWithRsa256Test()
            throws Exception {

        String rsaPublicKey = "-----BEGIN PUBLIC KEY-----MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1Vnj4ueHjaaoOb+h/Z+TswFRqQMMs0VCDSH7UonYwfTSs63efCSdbvRu23GVyr/wzVabYU7XF3Egxl/7WG8yMyPUWQsPnzB54OdwGX6CbAJTWZZmCQQb3F7wINNDkPHeXW1PirAEiU8szAWPDUa9U9G/YSmqtn3+niMv4aSJUaJ/4smKNkbQjl9pGofpV9c7VHTfKkvdoq5bjQvV+C8vFcA4GtLSDE/SLw3ksOHyArixda59txaz1xBhFmAfOgDpxtRGXVt7EyEnZtY+RC/mWYLCWUQBygWkfGMYiFWQAn3OSmPcoTNUSwhPE2n01eZyaSqzdStbhMhrdYjmAvBqhbxUu0EnyQDeFZnZVuHI6ZpE8DrhxmNuD8Xm5JOyReQMMyEjNqofPqlevtMpa8m0QaLpVkOVf11rMm2yjD6RTXG1jJxUjvoOZeWN9AEjN8Xzie82Uc9TZdIRZ6qJcDY22ra/Pum3aXgyGJZvXCb9h0NbGuuLo5WnotcU6VfaMsxvAgMBAAE=-----END PUBLIC KEY-----";
        String phoneNumber = "081574905117";
        String pin = "111111";

        rsaPublicKey = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("-----END PUBLIC KEY-----", "");

        byte[] publicBytes = Base64.getDecoder().decode(rsaPublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); //or try with "RSA"

        OAEPParameterSpec oaepParams =
                new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, oaepParams);
        byte[] encryptedPhoneNmber = cipher.doFinal(phoneNumber.getBytes());
        byte[] encryptedPIN = cipher.doFinal(pin.getBytes());

        String encryptedPhoneNumberString = Base64.getEncoder().encodeToString(encryptedPhoneNmber).replace("\n","").replace("\r","");
        String encryptedPINString = Base64.getEncoder().encodeToString(encryptedPIN).replace("\n","").replace("\r","");
        System.out.println("Encrypted Phone Number: " + encryptedPhoneNumberString);
        System.out.println("Encrypted PIN: " + encryptedPINString);

        Assertions.assertNotNull(encryptedPhoneNumberString);
    }

}
