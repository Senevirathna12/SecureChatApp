package client;

import util.*;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class ChatClient {
    private static PublicKey serverPublicKey;
    private static KeyPair clientKeyPair;
    private static SecretKey aesKey;

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            Scanner scanner = new Scanner(System.in);

            clientKeyPair = RSAUtil.generateKeyPair();

            // Receive server public key
            serverPublicKey = RSAUtil.getPublicKeyFromBase64(reader.readLine());

            // Send client's public key
            writer.write(Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded()));
            writer.newLine();
            writer.flush();

            // Login
            System.out.print(reader.readLine());
            String username = scanner.nextLine();
            writer.write(username);
            writer.newLine();
            writer.flush();

            System.out.print(reader.readLine());
            String password = scanner.nextLine();
            writer.write(password);
            writer.newLine();
            writer.flush();

            String loginStatus = reader.readLine();
            System.out.println(loginStatus);
            if (!loginStatus.startsWith("Login successful")) return;

            // Generate AES key and send it encrypted
            aesKey = AESEncryption.generateAESKey();
            String encryptedAES = RSAUtil.encryptAESKey(aesKey, serverPublicKey);
            writer.write(encryptedAES);
            writer.newLine();
            writer.flush();

            // Reader thread
            new Thread(() -> {
                try {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String[] parts = line.split("::");
                        if (parts.length != 3) continue;

                        String encrypted = parts[0];
                        String hmac = parts[1];
                        String signature = parts[2];

                        if (!HMACUtil.verifyHMAC(encrypted, aesKey, hmac)) {
                            System.out.println("[!] HMAC check failed.");
                            continue;
                        }

                        String decrypted = AESEncryption.decrypt(encrypted, aesKey);
                        if (!SignatureUtil.verify(decrypted, signature, serverPublicKey)) {
                            System.out.println("[!] Signature check failed.");
                            continue;
                        }

                        System.out.println(decrypted);
                    }
                } catch (Exception e) {
                    System.out.println("Disconnected from server.");
                }
            }).start();

            // Writer loop
            while (true) {
                String msg = scanner.nextLine();
                String encrypted = AESEncryption.encrypt(msg, aesKey);
                String hmac = HMACUtil.generateHMAC(encrypted, aesKey);
                String signature = SignatureUtil.sign(msg, clientKeyPair.getPrivate());

                writer.write(encrypted + "::" + hmac + "::" + signature);
                writer.newLine();
                writer.flush();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
