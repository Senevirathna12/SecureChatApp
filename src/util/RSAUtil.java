package util;

import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSAUtil {
    private static KeyPair keyPair;

    // Generate the RSA Key Pair (once during server startup)
    public static void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048); // 2048-bit key
        keyPair = generator.generateKeyPair();
    }

    // Get RSA Public Key (to send to client)
    public static PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    // Get RSA Public Key as Base64 string
    public static String getPublicKeyAsBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    // Decrypt AES key using RSA private key
    public static byte[] decryptWithPrivateKey(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        return cipher.doFinal(encryptedData);
    }
}
