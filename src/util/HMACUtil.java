package util;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.util.Base64;

public class HMACUtil {
    public static String generateHMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
    }

    public static boolean verifyHMAC(String data, SecretKey key, String receivedHMAC) throws Exception {
        String calculatedHMAC = generateHMAC(data, key);
        return calculatedHMAC.equals(receivedHMAC);
    }
}
