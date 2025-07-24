package server;

import util.AESEncryption;
import util.HMACUtil;
import util.RSAUtil;
import util.SignatureUtil;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

import javax.crypto.SecretKey;

public class ClientHandler implements Runnable {
    private Socket socket;
    private PublicKey serverPublicKey;
    private PrivateKey serverPrivateKey;
    private PublicKey clientPublicKey;
    private SecretKey aesKey;
    private String username;
    private BufferedReader reader;
    private BufferedWriter writer;

    public ClientHandler(Socket socket, KeyPair serverKeyPair) {
        this.socket = socket;
        this.serverPublicKey = serverKeyPair.getPublic();
        this.serverPrivateKey = serverKeyPair.getPrivate();
    }

    public void sendMessage(String message) throws Exception {
        String encrypted = AESEncryption.encrypt(message, aesKey);
        String hmac = HMACUtil.generateHMAC(encrypted, aesKey);
        String signature = SignatureUtil.sign(message, serverPrivateKey);

        writer.write(encrypted + "::" + hmac + "::" + signature);
        writer.newLine();
        writer.flush();
    }

    @Override
    public void run() {
        try {
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            // Send server public key
            writer.write(Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));
            writer.newLine();
            writer.flush();

            // Receive client's public key
            String clientPubKeyStr = reader.readLine();
            clientPublicKey = RSAUtil.getPublicKeyFromBase64(clientPubKeyStr);

            // Authenticate user
            writer.write("Enter username:");
            writer.newLine();
            writer.flush();
            String username = reader.readLine();

            writer.write("Enter password:");
            writer.newLine();
            writer.flush();
            String password = reader.readLine();

            if (!UserAuth.authenticate(username, password)) {
                writer.write("Authentication failed.");
                writer.newLine();
                writer.flush();
                socket.close();
                return;
            }

            this.username = username;
            ChatServer.clients.put(username, this);

            writer.write("Login successful. Welcome to the chat!");
            writer.newLine();
            writer.flush();
            System.out.println(username + " has joined the chat.");

            // === Key exchange starts here ===

            // Receive "username::nonce" from client
            String clientNonceLine = reader.readLine();
            String[] clientParts = clientNonceLine.split("::");
            if (clientParts.length != 2 || !clientParts[0].equals(username)) {
                writer.write("Invalid nonce exchange request.");
                writer.newLine();
                writer.flush();
                socket.close();
                return;
            }
            String nonce = clientParts[1];

            // Generate AES key
            aesKey = AESEncryption.generateAESKey();

            // Prepare payload "nonce::base64AESKey"
            String payload = nonce + "::" + AESEncryption.getBase64FromKey(aesKey);

            // Encrypt payload with client's public key
            byte[] encryptedPayloadBytes = RSAUtil.encrypt(payload.getBytes(), clientPublicKey);
            String encryptedPayload = Base64.getEncoder().encodeToString(encryptedPayloadBytes);

            // Sign the encrypted payload
            String signature = SignatureUtil.sign(encryptedPayload, serverPrivateKey);

            // Send encrypted payload and signature
            writer.write(encryptedPayload);
            writer.newLine();
            writer.write(signature);
            writer.newLine();
            writer.flush();

            // Receive client's confirmation "nonce+1" and signature
            String clientConfirm = reader.readLine();
            String clientConfirmSignature = reader.readLine();

            // Verify client's confirmation signature
            if (!SignatureUtil.verify(clientConfirm, clientConfirmSignature, clientPublicKey)) {
                System.out.println("Client nonce confirmation signature failed.");
                socket.close();
                return;
            }

            // Check nonce+1 correctness
            if (!clientConfirm.equals(nonce + "1")) {
                System.out.println("Client nonce confirmation value incorrect.");
                socket.close();
                return;
            }

            // === Key exchange ends here ===

            // Broadcast to others
            for (ClientHandler client : ChatServer.clients.values()) {
                if (!client.username.equals(this.username)) {
                    client.sendMessage(this.username + " has joined the chat.");
                }
            }

            String input;
            while ((input = reader.readLine()) != null) {
                String[] parts = input.split("::");
                if (parts.length != 3) continue;

                String encrypted = parts[0];
                String hmac = parts[1];
                String signature2 = parts[2];
                
                // System.out.println("encriped : " +encrypted + "hmac : "+ hmac + "signature: "+ signature2);

                // Step 1: Verify HMAC
                if (!HMACUtil.verifyHMAC(encrypted, aesKey, hmac)) {
                    System.out.println("HMAC verification failed.");
                    continue;
                }

                // Step 2: Decrypt
                String decrypted = AESEncryption.decrypt(encrypted, aesKey); // this is "msg::timestamp"

                // Step 3: Verify signature
                if (!SignatureUtil.verify(decrypted, signature2, clientPublicKey)) {
                    System.out.println("Signature verification failed.");
                    continue;
                }

                // Step 4: Split into message and timestamp
                String[] messageParts = decrypted.split("::");
                if (messageParts.length != 2) {
                    System.out.println("Invalid decrypted message format.");
                    continue;
                }

                String message = messageParts[0];
                long timestamp;
                try {
                    timestamp = Long.parseLong(messageParts[1]);
                } catch (NumberFormatException e) {
                    System.out.println("Invalid timestamp.");
                    continue;
                }

                // Step 5: Check timestamp validity
                long now = System.currentTimeMillis();
                if (Math.abs(now - timestamp) > 5000) { // 5 second window
                    System.out.println("Replay attack or delayed message detected. Ignored.");
                    continue;
                }

                // Step 6: Broadcast to others
                for (ClientHandler client : ChatServer.clients.values()) {
                    if (!client.username.equals(this.username)) {
                        client.sendMessage(this.username + ": " + message);
                    }
                }
            }


        } catch (Exception e) {
            System.out.println("Client disconnected: " + username);
        } finally {
            ChatServer.clients.remove(username);
        }
    }
}

