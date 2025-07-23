package client;
import util.AESEncryption;

import java.io.*;
import java.net.*;
import java.util.Scanner;

public class ChatClient {
    private static final String HOST = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) throws IOException {
        try (Socket socket = new Socket(HOST, PORT)) {
			BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
			try (Scanner scanner = new Scanner(System.in)) {
				// Thread to receive and display server messages
				new Thread(() -> {
				    try {
				        String serverMessage;
				        while ((serverMessage = reader.readLine()) != null) {
				            if (serverMessage.startsWith("[ENC]")) {
				                String base64Data = serverMessage.substring(5); // Remove [ENC]
				                String decrypted = AESEncryption.decrypt(base64Data);
				                System.out.println(decrypted);
				            } else {
				                // Plain system messages
				                System.out.println(serverMessage);
				            }
				        }


				    } catch (IOException ignored) {}
				}).start();

				while (true) {  
				    String userInput = scanner.nextLine().trim();
				    if (!userInput.isEmpty()) {
				        String encrypted = AESEncryption.encrypt(userInput);  //  Encrypt before sending
				        writer.println(encrypted);
				        // System.out.println("input"+encrypted);
				    }

				}

			}
		}
    }
}
