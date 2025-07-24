package util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static PublicKey getPublicKeyFromBase64(String base64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }

    // Encrypt byte array with RSA public key
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Decrypt byte array with RSA private key
    public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(data);
        return new String(decrypted);
    }

    public static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(aesKey.getEncoded()));
    }

    public static SecretKey decryptAESKey(String encrypted, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new SecretKeySpec(decoded, 0, decoded.length, "AES");
    }
}
