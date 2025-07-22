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
            writer.println("Enter username:");
            String username = reader.readLine();

            writer.println("Enter password:");
            String password = reader.readLine();

            if (!UserAuth.authenticate(username, password)) {
                writer.println("Authentication failed. Connection closed.");
                socket.close();
                return;
            }

            writer.println("Login successful. Welcome to the chat!");

            broadcast(username + " has joined the chat.");

            String message;
            while ((message = reader.readLine()) != null) {
//                broadcast(username + ": " + message);
            	String decryptedMessage = util.AESEncryption.decrypt(message);
            	System.out.println("Received (decrypted): " + decryptedMessage);
            	broadcast(util.AESEncryption.encrypt(username + ": " + decryptedMessage));

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
