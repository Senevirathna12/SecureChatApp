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
//				    String serverMessage;
				    try {
//				        while ((serverMessage = reader.readLine()) != null) {
//				            System.out.println(serverMessage);
//				        }
				    	
				        String encryptedMessage;
				        while ((encryptedMessage = reader.readLine()) != null) {
				            String decrypted = AESEncryption.decrypt(encryptedMessage);  // Decrypt after receiving
				            System.out.println(decrypted);
				        }

				    } catch (IOException ignored) {}
				}).start();

				// Thread to send user input
				while (true) {
//				    String userInput = scanner.nextLine().trim();
//				    if (!userInput.isEmpty()) {
//				        writer.println(userInput);
//				    }
				    
				    String userInput = scanner.nextLine().trim();
				    if (!userInput.isEmpty()) {
				        String encrypted = AESEncryption.encrypt(userInput);  //  Encrypt before sending
				        writer.println(encrypted);
				    }

				}

			}
		}
    }
}
