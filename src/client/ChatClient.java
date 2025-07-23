package client;

import util.AESEncryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

public class ChatClient {
    private static final String HOST = "localhost";
    private static final int PORT = 12345;

    private static byte[] aesKey; // shared AES key for this client session

    public static void main(String[] args) {
        try (Socket socket = new Socket(HOST, PORT)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            // Step 1: Receive RSA Public Key from server
            String publicKeyBase64 = reader.readLine();
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey serverPublicKey = keyFactory.generatePublic(keySpec);

            // Step 2: Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // 128-bit AES
            SecretKey secretKey = keyGen.generateKey();
            aesKey = secretKey.getEncoded(); // Store AES key

            // Step 3: Encrypt AES key with server RSA public key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAESKey = rsaCipher.doFinal(aesKey);
            String encryptedAESKeyBase64 = Base64.getEncoder().encodeToString(encryptedAESKey);

            // Step 4: Send encrypted AES key to server
            writer.println(encryptedAESKeyBase64);
            writer.flush();

            Scanner scanner = new Scanner(System.in);

            // Step 5: Read login prompts
            System.out.println(reader.readLine()); // "Enter username:"
            String username = scanner.nextLine();
            writer.println(AESEncryption.encrypt(username, aesKey));

            System.out.println(reader.readLine()); // "Enter password:"
            String password = scanner.nextLine();
            writer.println(AESEncryption.encrypt(password, aesKey));

            // Step 6: Start listener for messages from server
            new Thread(() -> {
                try {
                    String serverMessage;
                    while ((serverMessage = reader.readLine()) != null) {
                        if (serverMessage.startsWith("[ENC]")) {
                            String encryptedPayload = serverMessage.substring(5);
                            String decrypted = AESEncryption.decrypt(encryptedPayload, aesKey);
                            System.out.println(decrypted);
                        } else {
                            System.out.println(serverMessage); // System or error messages
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();

            // Step 7: Send encrypted messages
            while (true) {
                String userInput = scanner.nextLine().trim();
                if (!userInput.isEmpty()) {
                    String encrypted = AESEncryption.encrypt(userInput, aesKey);
                    writer.println(encrypted);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
