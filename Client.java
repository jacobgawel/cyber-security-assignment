import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Client {
    public static void main(String[] args) throws
            NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException {

        if (args.length != 3) {
            System.err.println("Usage: java Client host port userId");
            System.exit(-1);
        }

        System.out.println("Client program (user " + args[2] + ")");
        System.out.println("--------------");

        // assign the essential variables from the arguments that we need to get assign the port, host and private key
        // e.g. the userId is the name of the private key file
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2]; // <------ userid variable
        String privateFilename = args[2] + ".prv";
        String publicFilename = "server.pub";

        String dir = System.getProperty("user.dir");
        String privateKeyPath = dir + "\\" + privateFilename;
        String publicKeyPath = dir + "\\" + publicFilename;

        PrivateKey privateKey = null;
        try {
            File privateFile = new File(privateKeyPath);
            FileInputStream privateFis = new FileInputStream(privateFile);
            byte[] privateKeyBytes = new byte[(int) privateFile.length()];
            privateFis.read(privateKeyBytes);
            privateFis.close();

            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
            privateKey = privateKeyFactory.generatePrivate(privateSpec);
        } catch (FileNotFoundException ex) {
            System.err.println("No private key file for the userId found in the client directory");
            System.exit(-1);
        }

        PublicKey publicKey = null;
        try {
            File publicFile = new File(publicKeyPath);
            FileInputStream publicFis = new FileInputStream(publicFile);
            byte[] publicKeyBytes = new byte[(int) publicFile.length()];
            publicFis.read(publicKeyBytes); // Corrected variable name here
            publicFis.close();

            // Generate the public key
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
            publicKey = publicKeyFactory.generatePublic(publicSpec);
        } catch (FileNotFoundException ex) {
            System.err.println("No server public key found in the client directory");
            System.exit(-1);
        }

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
            List<String> serverEncryptedMessages = new ArrayList<>();
            List<byte[]> serverMessageSignatures = new ArrayList<>();

            int signatureSize = 0;
            while (true) {
                // The if statements are used to tell the client side when to stop and break from the loop
                String message = dis.readUTF();
                if ("LENGTH".equals(message)) {
                    signatureSize = Integer.parseInt(dis.readUTF());
                }
                if ("SIGNATURE".equals(message)) {
                    byte[] signature = new byte[signatureSize];
                    dis.readFully(signature);
                    serverMessageSignatures.add(signature);
                }
                if ("NO_SERVER_MESSAGES".equals(message)) {
                    break;
                }
                if ("END_OF_SERVER_MESSAGE".equals(message)) {
                    break;
                }
                if ("MESSAGE".equals(message)) {
                    message = dis.readUTF();
                    serverEncryptedMessages.add(message);
                }
            }

            System.out.println("There are " + serverEncryptedMessages.size() + " message(s) for you.\n");

            for (int i = 0; i < serverEncryptedMessages.size(); i++) {
                var result = verifySignature(serverEncryptedMessages.get(i),
                        serverMessageSignatures.get(i), publicKeyPath);
                if (!result) { // terminate the program immediately if the signature fails
                    dis.close();
                    System.exit(-1);
                }

                String[] splitMessage = serverEncryptedMessages.get(i).split(",");
                String decryptedMessage = new String(decryptCipher.doFinal(Base64.getDecoder().decode(splitMessage[0])));
                String decryptedTimestamp = new String(decryptCipher.doFinal(Base64.getDecoder().decode(splitMessage[1])));
                System.out.println("Date: " + decryptedTimestamp + "\nMessage: " + decryptedMessage + "\n");
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
            dos.writeUTF(Base64.getEncoder().encodeToString(encryptedRecipient));

            System.out.print("Enter your message: ");
            String message = scanner.nextLine();

            byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            dos.writeUTF(Base64.getEncoder().encodeToString(encryptedMessage));

            dos.writeUTF("END_OF_CLIENT_MESSAGE"); // Signal the end of message

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

    public static boolean verifySignature(String serverEncryptedMessage, byte[] serverMessageSignature, String publicKeyPath)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {

        File file = new File(publicKeyPath);
        byte[] publicKeyBytes = Files.readAllBytes(file.toPath());

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(publicKeySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(pk);

        signature.update(serverEncryptedMessage.getBytes());

        return signature.verify(serverMessageSignature);
    }
}
