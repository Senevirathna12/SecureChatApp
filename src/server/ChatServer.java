package server;


import java.io.*;
import util.RSAUtil;

import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class ChatServer {
    private static final int PORT = 12345;
    private static Set<ClientHandler> clientHandlers = new HashSet<>();

    public static void main(String[] args) throws IOException {
    	
    	// Generate RSA keys once
        try {
            RSAUtil.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return; 
        }

        System.out.println("RSA Public Key (Base64):");
        System.out.println(RSAUtil.getPublicKeyAsBase64());
    	
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
			System.out.println("Chat server started on port " + PORT);

			while (true) {
			    Socket socket = serverSocket.accept();
			    System.out.println("New client connected: " + socket);

			    ClientHandler clientHandler = new ClientHandler(socket, clientHandlers);
			    clientHandlers.add(clientHandler);
			    new Thread(clientHandler).start();
			}
		}
    }
}
