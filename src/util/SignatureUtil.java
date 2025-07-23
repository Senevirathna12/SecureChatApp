package util;

import java.security.*;
import java.util.Base64;

public class SignatureUtil {
    public static String sign(String data, PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public static boolean verify(String data, String signatureStr, PublicKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(data.getBytes());
        return signature.verify(Base64.getDecoder().decode(signatureStr));
    }
}
