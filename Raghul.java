import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

public class Raghul extends JFrame {
    private JButton selectFileButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private JTextArea outputArea;
    private JLabel instructionsLabel;
    private File selectedFile;
    private String PASS;
    private static final String SECRET_KEY = "1234567890123456";
    private static final Map<String, String> USERS = new HashMap<>();

    static {
        USERS.put("rahul", "java123");
        USERS.put("user1", "pass1");
        USERS.put("user2", "pass2");
        USERS.put("user3", "pass3");
    }

    public Raghul() {

        PASS = JOptionPane.showInputDialog("Enter Password:");

        // Initial login dialog
        login();

        setTitle("File Encrypt/Decrypt");
        setSize(600, 500);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(3, 1));

        selectFileButton = new JButton("Select File");
        panel.add(selectFileButton);

        encryptButton = new JButton("Encrypt");
        panel.add(encryptButton);

        decryptButton = new JButton("Decrypt");
        panel.add(decryptButton);

        add(panel, BorderLayout.NORTH);

        outputArea = new JTextArea();
        add(new JScrollPane(outputArea), BorderLayout.CENTER);

        instructionsLabel = new JLabel("<html>1. First, select the file which you want to encrypt or decrypt.<br>" +
                "2. After selecting the file, you can press the Encrypt or Decrypt button.<br>" +
                "3. If encrypted, it will save with the extension of .enc.<br>" +
                "   If decrypted, it will save with the extension of .dec.</html>");
        instructionsLabel.setHorizontalAlignment(SwingConstants.CENTER);
        add(instructionsLabel, BorderLayout.SOUTH);

        // Action listeners
        selectFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int option = fileChooser.showOpenDialog(Raghul.this);
                if (option == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                    outputArea.setText("Selected file: " + selectedFile.getAbsolutePath());
                }
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (selectedFile == null) {
                    outputArea.setText("Please select a file first.");
                    return;
                }
                try {
                    String newFileName = getNewFileName(selectedFile, "enc");
                    encryptFile(selectedFile.getAbsolutePath(), SECRET_KEY, newFileName);
                    outputArea.append("\nFile encrypted successfully! Saved as: " + newFileName);
                    selectedFile = null; // Reset the selected file
                } catch (Exception ex) {
                    outputArea.append("\nError: " + ex.getMessage());
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (selectedFile == null) {
                    outputArea.setText("Please select a file first.");
                    return;
                }
                try {
                    String newFileName = getNewFileName(selectedFile, "dec");
                    decryptFile(selectedFile.getAbsolutePath(), SECRET_KEY, newFileName);
                    outputArea.append("\nFile decrypted successfully! Saved as: " + newFileName);
                    selectedFile = null; // Reset the selected file
                } catch (Exception ex) {
                    outputArea.append("\nError: " + ex.getMessage());
                }
            }
        });
    }

    private void login() {
        JTextField idField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        Object[] message = {
                "ID:", idField,
                "Password:", passwordField
        };

        int option = JOptionPane.showConfirmDialog(null, message, "Login", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String enteredId = idField.getText();
            String enteredPassword = new String(passwordField.getPassword());

            boolean loginSuccessful = USERS.containsKey(enteredId) && USERS.get(enteredId).equals(enteredPassword);
            logLoginAttempt(enteredId, enteredPassword, loginSuccessful);

            if (loginSuccessful) {
                // Login successful
                return;
            } else {
                // Login failed
                JOptionPane.showMessageDialog(null, "ID or Password is incorrect", "Error", JOptionPane.ERROR_MESSAGE);
                login();
            }
        } else {
            System.exit(0);
        }
    }

    private void logLoginAttempt(String userId, String password, boolean successful) {
        String url = "jdbc:mysql://localhost:3306/";
        String dbUsername = "root";
        String dbPassword = PASS;

        try (Connection connection = DriverManager.getConnection(url, dbUsername, dbPassword)) {
            // Create database 'demo1' if not exists
            String createDB = "CREATE DATABASE IF NOT EXISTS demo1";
            try (PreparedStatement statement = connection.prepareStatement(createDB)) {
                statement.execute();
            }

            // Use database 'demo1'
            String useDB = "USE demo1";
            try (PreparedStatement statement = connection.prepareStatement(useDB)) {
                statement.execute();
            }

            // Create table 'login_attempts' if not exists
            String createTable = "CREATE TABLE IF NOT EXISTS login_attempts (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY," +
                    "user_id VARCHAR(255) NOT NULL," +
                    "password VARCHAR(255) NOT NULL," +
                    "successful BOOLEAN DEFAULT FALSE," +
                    "unsuccessful BOOLEAN DEFAULT FALSE," +
                    "attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ") ENGINE=InnoDB";
            try (PreparedStatement statement = connection.prepareStatement(createTable)) {
                statement.execute();
            }

            // Insert login attempt record
            String sql = "INSERT INTO login_attempts (user_id, password, successful, unsuccessful, attempt_time) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, userId);
                statement.setString(2, password);
                statement.setBoolean(3, successful);
                statement.setBoolean(4, !successful);
                statement.setTimestamp(5, new Timestamp(System.currentTimeMillis()));
                statement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private String getNewFileName(File file, String suffix) {
        String filePath = file.getAbsolutePath();
        int dotIndex = filePath.lastIndexOf('.');
        if (dotIndex != -1) {
            filePath = filePath.substring(0, dotIndex);
        }
        return filePath + "." + suffix;
    }

    private void encryptFile(String filePath, String key, String newFileName) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        byte[] encryptedData = encrypt(fileData, key);
        Files.write(Paths.get(newFileName), encryptedData);
    }

    private void decryptFile(String filePath, String key, String newFileName) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        byte[] decryptedData = decrypt(fileData, key);
        Files.write(Paths.get(newFileName), decryptedData);
    }

    private byte[] encrypt(byte[] data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new Raghul().setVisible(true);
            }
        });
    }
}