package util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESEncryption {
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static String encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String decrypt(String cipherText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    // Convert AES key to Base64 string
    public static String getBase64FromKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Convert Base64 string back to AES key
    public static SecretKey getKeyFromBase64(String base64Key) {
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(decoded, 0, decoded.length, "AES");
    }
}
