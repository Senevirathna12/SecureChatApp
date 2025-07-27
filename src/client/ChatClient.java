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
            try (Scanner scanner = new Scanner(System.in)) {
				clientKeyPair = RSAUtil.generateKeyPair();

				// Send client's public key first
				writer.write(Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded()));
				writer.newLine();
				writer.flush();

				// Receive server public key
				serverPublicKey = RSAUtil.getPublicKeyFromBase64(reader.readLine());

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

				// === Key exchange starts here ===

				// Step 1: Client generates nonce and sends "username::nonce"
				String nonce = CryptoUtil.generateNonce(); // You need a method to generate nonce (random string)
				writer.write(username + "::" + nonce);
				writer.newLine();
				writer.flush();

				// Step 2: Receive encrypted (nonce::aesKey) and signature from server
				String encryptedPayload = reader.readLine();
				String signature = reader.readLine();

				// Step 3: Verify server's signature on encrypted payload
				if (!SignatureUtil.verify(encryptedPayload, signature, serverPublicKey)) {
				    System.out.println("[!] Signature verification failed on key exchange.");
				    return;
				}

				// Step 4: Decrypt the payload with client's private key
				String decrypted = RSAUtil.decrypt(
				        Base64.getDecoder().decode(encryptedPayload),
				        clientKeyPair.getPrivate());

				String[] parts = decrypted.split("::");
				if (parts.length != 2 || !parts[0].equals(nonce)) {
				    System.out.println("[!] Nonce mismatch — possible replay attack.");
				    return;
				}

				aesKey = AESEncryption.getKeyFromBase64(parts[1]);

				// Step 5: Send confirmation "nonce+1" back to server, signed by client
				String noncePlusOne = nonce + "1";
				String signedNoncePlusOne = SignatureUtil.sign(noncePlusOne, clientKeyPair.getPrivate());
				writer.write(noncePlusOne);
				writer.newLine();
				writer.write(signedNoncePlusOne);
				writer.newLine();
				writer.flush();

				// === Key exchange ends here ===

				// Reader thread
				new Thread(() -> {
				    try {
				        String line;
				        while ((line = reader.readLine()) != null) {
				            String[] parts2 = line.split("::");
				            if (parts2.length != 3) continue;

				            String encrypted = parts2[0];
				            String hmac = parts2[1];
				            String signature2 = parts2[2];

				            if (!HMACUtil.verifyHMAC(encrypted, aesKey, hmac)) {
				                System.out.println("[!] HMAC check failed.");
				                continue;
				            }

				            String decryptedMsg = AESEncryption.decrypt(encrypted, aesKey);
				            if (!SignatureUtil.verify(encrypted, signature2, serverPublicKey)) {
				                System.out.println("[!] Signature check failed.");
				                continue;
				            }

				            System.out.println(decryptedMsg);
				        }
				    } catch (Exception e) {
				        System.out.println("Disconnected from server.");
				    }
				}).start();

				// Writer loop
				while (true) {
				    String msg = scanner.nextLine();
				    long timestamp = System.currentTimeMillis();
				    String payload = msg + "::" + timestamp;

				    String encrypted = AESEncryption.encrypt(payload, aesKey);
				    String hmac = HMACUtil.generateHMAC(encrypted, aesKey);
				    String signature2 = SignatureUtil.sign(encrypted, clientKeyPair.getPrivate());

				    writer.write(encrypted + "::" + hmac + "::" + signature2);
				    writer.newLine();
				    writer.flush();
				}
			}


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
