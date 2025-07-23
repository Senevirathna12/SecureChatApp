package server;

import util.AESEncryption;
import util.HMACUtil;
import util.RSAUtil;
import util.SignatureUtil;
import server.UserAuth;

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

            // Receive AES key encrypted with server's public key
            String encAESKey = reader.readLine();
            aesKey = RSAUtil.decryptAESKey(encAESKey, serverPrivateKey);

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
                String signature = parts[2];

                if (!HMACUtil.verifyHMAC(encrypted, aesKey, hmac)) {
                    System.out.println("HMAC verification failed.");
                    continue;
                }

                String decrypted = AESEncryption.decrypt(encrypted, aesKey);

                if (!SignatureUtil.verify(decrypted, signature, clientPublicKey)) {
                    System.out.println("Signature verification failed.");
                    continue;
                }

                // System.out.println(username + ": " + decrypted);

                for (ClientHandler client : ChatServer.clients.values()) {
                    if (!client.username.equals(this.username)) {
                        client.sendMessage(this.username + ": " + decrypted);
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
