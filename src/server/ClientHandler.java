package server;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.Base64;

import util.AESEncryption;
import util.RSAUtil;

public class ClientHandler implements Runnable {
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private Set<ClientHandler> clients;

    private byte[] aesKey; // Store AES key per client

    public ClientHandler(Socket socket, Set<ClientHandler> clients) throws IOException {
        this.socket = socket;
        this.clients = clients;
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        writer = new PrintWriter(socket.getOutputStream(), true);
    }

    public void run() {
        try {
            // 🔐 Step 1: Send RSA public key to client
            String publicKeyBase64 = RSAUtil.getPublicKeyAsBase64();
            writer.println(publicKeyBase64); // client reads this first

            // 🔐 Step 2: Receive encrypted AES key from client
            String encryptedAESKeyBase64 = reader.readLine();
            byte[] encryptedAESKey = Base64.getDecoder().decode(encryptedAESKeyBase64);

            // 🔐 Step 3: Decrypt AES key using RSA private key
            aesKey = RSAUtil.decryptWithPrivateKey(encryptedAESKey);

            // ✅ Proceed with login using AES
            writer.println("Enter username:");
            String encryptedUsername = reader.readLine();
            String username = AESEncryption.decrypt(encryptedUsername, aesKey);

            writer.println("Enter password:");
            String encryptedPassword = reader.readLine();
            String password = AESEncryption.decrypt(encryptedPassword, aesKey);

            if (!UserAuth.authenticate(username, password)) {
                writer.println("Authentication failed. Connection closed.");
                socket.close();
                return;
            }

            writer.println("Login successful. Welcome to the chat!");
            broadcast("[ENC]" + AESEncryption.encrypt(username + " has joined the chat.", aesKey));

            String message;
            while ((message = reader.readLine()) != null) {
                String decryptedMessage = AESEncryption.decrypt(message, aesKey);
                broadcast("[ENC]" + AESEncryption.encrypt(username + ": " + decryptedMessage, aesKey));
            }

        } catch (Exception e) {
            System.out.println("Client disconnected: " + socket);
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {}
        }
    }

    private void broadcast(String message) {
        for (ClientHandler client : clients) {
            client.writer.println(message);
        }
    }
}
