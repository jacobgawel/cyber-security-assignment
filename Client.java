import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) throws
            NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException {

        if (args.length != 3) {
            System.err.println("Usage: java Client host port userId");
            System.exit(-1);
        }

        System.out.println("Client program (user " + args[2] + ")");
        System.out.println("--------------");

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2]; // <------ userid variable
        String privateFilename = args[2] + ".prv";
        String publicFilename = "server.pub";

        String dir = System.getProperty("user.dir");
        String privateKeyPath = dir + "\\" + privateFilename;
        String publicKeyPath = dir + "\\" + publicFilename;

        File privateFile = new File(privateKeyPath);
        FileInputStream privateFis = new FileInputStream(privateFile);
        byte[] privateKeyBytes = new byte[(int) privateFile.length()];
        privateFis.read(privateKeyBytes);
        privateFis.close();

        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = privateKeyFactory.generatePrivate(privateSpec);

        File publicFile = new File(publicKeyPath);
        FileInputStream publicFis = new FileInputStream(publicFile);
        byte[] publicKeyBytes = new byte[(int) publicFile.length()];
        publicFis.read(publicKeyBytes); // Corrected variable name here
        publicFis.close();

        // Generate the public key
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = publicKeyFactory.generatePublic(publicSpec);

        // Encrypt data
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Decrypt data
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        try {
            String userHash = GetHashFromUser(args); // Assume this function exists and works as intended
            Socket socket = new Socket(host, port);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            DataInputStream dis = new DataInputStream(socket.getInputStream());

            // Send user hash first before attempting to read messages
            byte[] encryptedUserHash = cipher.doFinal(userHash.getBytes());
            dos.writeUTF(Base64.getEncoder().encodeToString(encryptedUserHash));

            // Now, start reading messages from the server
            List<String> serverMessage = new ArrayList<>();
            while(true) {
                String message = dis.readUTF();
                if ("NO_SERVER_MESSAGES".equals(message)) {
                    break;
                }
                if("END_OF_SERVER_MESSAGE".equals(message)) {
                    break;
                }
                // TODO: Might need some exception handling over here for the incorrect ciphers etc
                String decryptedMessage = new String(decryptCipher.doFinal(Base64.getDecoder().decode(message)));
                serverMessage.add(decryptedMessage);
            }

            System.out.println("There are " + serverMessage.size() / 2 + " message(s) for you.\n");

            // Print messages received from the server
            for (int i = 0; i < serverMessage.size(); i += 2) {
                String message = serverMessage.get(i);
                String date = serverMessage.get(i + 1);

                System.out.println("Date: " + date + "\nMessage: " + message + "\n");
            }

            Scanner scanner = new Scanner(System.in);

            System.out.print("Do you want to send a message? [y/n]: ");
            String userInput = scanner.nextLine();

            if (userInput.equals("n")) {
                System.exit(-1);
            }

            // After processing server messages, send client messages
            byte[] encryptedUserId = cipher.doFinal(userId.getBytes());
            dos.writeUTF(Base64.getEncoder().encodeToString(encryptedUserId));

            System.out.print("Enter the recipient userid: ");
            String recipient = scanner.nextLine();

            byte[] encryptedRecipient = cipher.doFinal(recipient.getBytes());
            dos.writeUTF(Base64.getEncoder().encodeToString(encryptedRecipient)); // Assuming "bob" is the recipient

            System.out.print("Enter your message: ");
            String message = scanner.nextLine();

            byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            dos.writeUTF(Base64.getEncoder().encodeToString(encryptedMessage)); // The message

            dos.writeUTF("END_OF_CLIENT_MESSAGE"); // Signal the end of messages

        } catch (Exception exception) {
            System.err.println(exception);
        }

    }

    public static String GetHashFromUser(String[] args) throws NoSuchAlgorithmException {
        // creates and returns the hash with appended secret string

        MessageDigest md = MessageDigest.getInstance("MD5");

        String user = "gfhk2024:" + args[2];

        byte[] bytes = user.getBytes();
        byte[] digest = md.digest(bytes);

        StringBuilder sb = new StringBuilder();

        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }
}
