package util;

import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtil {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    public static String generateNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        secureRandom.nextBytes(nonce);
        return base64Encoder.encodeToString(nonce);
    }

    // Overloaded method with default nonce size
    public static String generateNonce() {
        return generateNonce(16); // 16 bytes nonce (128 bits)
    }
}
