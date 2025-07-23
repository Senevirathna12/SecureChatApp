package server;

import util.RSAUtil;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.HashMap;

public class ChatServer {
    private static final int PORT = 12345;
    public static KeyPair rsaKeyPair;
    public static HashMap<String, ClientHandler> clients = new HashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            rsaKeyPair = RSAUtil.generateKeyPair();
            System.out.println("Server started. Waiting for clients...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new ClientHandler(clientSocket, rsaKeyPair)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
