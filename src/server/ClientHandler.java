package server;

import java.io.*;
import java.net.*;
import java.util.*;

public class ClientHandler implements Runnable {
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private Set<ClientHandler> clients;

    public ClientHandler(Socket socket, Set<ClientHandler> clients) throws IOException {
        this.socket = socket;
        this.clients = clients;
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        writer = new PrintWriter(socket.getOutputStream(), true);
    }


    public void run() {
        try {
        	writer.println("Enter username:"); // Sent to client
        	String encryptedUsername = reader.readLine(); // Read encrypted
        	String username = util.AESEncryption.decrypt(encryptedUsername); // Decrypt

        	// System.out.println("Received username : " + encryptedUsername); 
        	// System.out.println("Received username (decrypted): " + username);

        	writer.println("Enter password:"); // Sent to client
        	String encryptedPassword = reader.readLine(); // Read encrypted
        	String password = util.AESEncryption.decrypt(encryptedPassword); // Decrypt

        	// System.out.println("Received password : " + encryptedPassword); 
        	// System.out.println("Received password (decrypted): " + password);
        	
        	// Now authenticate with decrypted values
        	if (!UserAuth.authenticate(username, password)) {
        	    writer.println("Authentication failed. Connection closed.");
        	    socket.close();
        	    return;
        	}

        	writer.println("Login successful. Welcome to the chat!");
        	broadcast("[ENC]" + util.AESEncryption.encrypt(username + " has joined the chat."));

        	String message;
        	while ((message = reader.readLine()) != null) {
        	    String decryptedMessage = util.AESEncryption.decrypt(message); // Decrypt incoming message
        	    // System.out.println("Received (decrypted): " + decryptedMessage);
        	    broadcast("[ENC]" + util.AESEncryption.encrypt(username + ": " + decryptedMessage)); // Encrypt and tag
        	}


        } catch (IOException e) {
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
