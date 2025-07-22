package client;

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
				System.out.print("Enter your name: ");
				String name = scanner.nextLine();
				writer.println(name); // Send name first

				// Listen for server messages
				new Thread(() -> {
				    String serverMessage;
				    try {
				        while ((serverMessage = reader.readLine()) != null) {
				            System.out.println(serverMessage);
				        }
				    } catch (IOException ignored) {}
				}).start();

				// Send messages
				while (true) {
				    String msg = scanner.nextLine();
				    writer.println(msg);
				}
			}
		}
    }
}
