package client;

import util.*;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class ChatclientUI extends JFrame {
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton sendButton;

    private BufferedReader reader;
    private BufferedWriter writer;
    private PublicKey serverPublicKey;
    private KeyPair clientKeyPair;
    private SecretKey aesKey;
    private String username;
    private PublicKey serverKey;
    private Socket socket;

    public ChatclientUI() {
        initUI();
        loginAndConnect();
    }

    private void initUI() {
        setTitle("Secure Chat");
        setSize(400, 500);
        setLayout(new BorderLayout());

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane pane = new JScrollPane(chatArea);
        add(pane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        messageField = new JTextField();
        sendButton = new JButton("Send");

        bottomPanel.add(messageField, BorderLayout.CENTER);
        bottomPanel.add(sendButton, BorderLayout.EAST);
        add(bottomPanel, BorderLayout.SOUTH);

        sendButton.addActionListener(e -> sendMessage());

        messageField.addActionListener(e -> sendMessage());

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setVisible(true);
    }

    private void loginAndConnect() {
        try {
            username = JOptionPane.showInputDialog(this, "Enter username:");
            String password = JOptionPane.showInputDialog(this, "Enter password:");

            socket = new Socket("localhost", 12345);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            serverPublicKey = RSAUtil.getPublicKeyFromBase64(reader.readLine());

            clientKeyPair = RSAUtil.generateKeyPair();
            writer.write(Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded()));
            writer.newLine();
            writer.flush();

            reader.readLine(); // "Enter username:"
            writer.write(username);
            writer.newLine();
            writer.flush();

            reader.readLine(); // "Enter password:"
            writer.write(password);
            writer.newLine();
            writer.flush();

            String authResponse = reader.readLine();
            if (!authResponse.contains("successful")) {
                JOptionPane.showMessageDialog(this, "Authentication failed.");
                socket.close();
                System.exit(0);
            }

            appendToChat(authResponse);

            // === Secure Key Exchange ===
            String nonce = String.valueOf(System.currentTimeMillis());
            writer.write(username + "::" + nonce);
            writer.newLine();
            writer.flush();

            // Receive encrypted AES key + signature
            String encryptedAESPayload = reader.readLine();
            String signature = reader.readLine();

            // Verify signature
            if (!SignatureUtil.verify(encryptedAESPayload, signature, serverPublicKey)) {
                appendToChat("Signature verification failed.");
                socket.close();
                return;
            }

            String decryptedPayload = new String(RSAUtil.decrypt(Base64.getDecoder().decode(encryptedAESPayload), clientKeyPair.getPrivate()));
            String[] payloadParts = decryptedPayload.split("::");
            if (!payloadParts[0].equals(nonce)) {
                appendToChat("Invalid nonce confirmation.");
                socket.close();
                return;
            }

            aesKey = AESEncryption.getKeyFromBase64(payloadParts[1]);

            // Send confirmation
            writer.write(nonce + "1");
            writer.newLine();
            writer.write(SignatureUtil.sign(nonce + "1", clientKeyPair.getPrivate()));
            writer.newLine();
            writer.flush();

            // Start reading incoming messages
            new Thread(this::receiveMessages).start();

        } catch (Exception e) {
            appendToChat("Error connecting: " + e.getMessage());
        }
    }

    private void sendMessage() {
        try {
            String message = messageField.getText().trim();
            if (message.isEmpty()) return;

            long timestamp = System.currentTimeMillis();
            String msgWithTime = message + "::" + timestamp;

            String encrypted = AESEncryption.encrypt(msgWithTime, aesKey);
            String hmac = HMACUtil.generateHMAC(encrypted, aesKey);
            String signature = SignatureUtil.sign(msgWithTime, clientKeyPair.getPrivate());

            writer.write(encrypted + "::" + hmac + "::" + signature);
            writer.newLine();
            writer.flush();

            messageField.setText("");
            appendToChat("Me: " + message);

        } catch (Exception e) {
            appendToChat("Send failed: " + e.getMessage());
        }
    }

    private void receiveMessages() {
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("::");
                if (parts.length < 3) continue;

                String encrypted = parts[0];
                String hmac = parts[1];
                String signature = parts[2];

                if (!HMACUtil.verifyHMAC(encrypted, aesKey, hmac)) {
                    appendToChat("⚠ HMAC verification failed.");
                    continue;
                }

                String decrypted = AESEncryption.decrypt(encrypted, aesKey);
                if (!SignatureUtil.verify(decrypted, signature, serverPublicKey)) {
                    appendToChat("⚠ Signature verification failed.");
                    continue;
                }

                String[] msgParts = decrypted.split("::");
                String msg = msgParts[0];
                appendToChat(msg);
            }
        } catch (Exception e) {
            appendToChat("Disconnected.");
        }
    }

    private void appendToChat(String msg) {
        SwingUtilities.invokeLater(() -> {
            chatArea.append(msg + "\n");
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(ChatclientUI::new);
    }
}