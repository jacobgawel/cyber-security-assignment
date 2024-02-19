import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Server {
    static List<String[]> Messages = new ArrayList<>();

    public static void main(String[] args) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        // tries to get the port from the command line argument

        int port;
        String serverPrivateFilename = "server.prv";
        String dir = System.getProperty("user.dir");
        String serverPrivateKeyPath = dir + "\\" + serverPrivateFilename;
        if (args.length != 1) {
            System.err.println("Usage: java Server port");
            System.exit(-1);
        }

        PrivateKey serverPrivateKey = null;

        try {
            serverPrivateKey = GetServerPrivateKey(serverPrivateKeyPath);
        } catch (FileNotFoundException ex) {
            System.err.println("Please generate a server private + public key before running the server");
            System.exit(-1);
        }

        Cipher serverCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        serverCipherDecrypt.init(Cipher.DECRYPT_MODE, serverPrivateKey);

        port = Integer.parseInt(args[0]);

        ServerSocket socketServer = new ServerSocket(port);

        // Generate signature for the server
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(serverPrivateKey);

        System.out.println("Server program");
        System.out.println("--------------");

        LogMessage("alice", "bob", "hello world");

        while(true) {

            try {
                Socket socket = socketServer.accept();
                DataInputStream dis = new DataInputStream(socket.getInputStream());
                DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

                // the client connects to the server and passes through the hashed userId
                String userHash = dis.readUTF();
                userHash = new String(serverCipherDecrypt.doFinal(Base64.getDecoder().decode(userHash)));

                List<String[]> messagesForClient = GetMessageForUser(userHash);

                if (!messagesForClient.isEmpty()) {
                    // the client will then loop and send back the encrypted message back to the client
                    // the message is encrypted using the pub key that is linked to the hashed id
                    for (String[] message : messagesForClient) {
                        dos.writeUTF("MESSAGE");
                        String serverMessage = message[2] + "," + message[3];
                        dos.writeUTF(serverMessage);
                        // create signature and send it to client
                        sig.update(serverMessage.getBytes());
                        byte[] signature = sig.sign();
                        int lengthOfByte = signature.length;
                        dos.writeUTF("LENGTH");
                        dos.writeUTF(String.valueOf(lengthOfByte));
                        dos.writeUTF("SIGNATURE");
                        dos.write(signature);
                    }
                    dos.writeUTF("END_OF_SERVER_MESSAGE");
                } else {
                    dos.writeUTF("NO_SERVER_MESSAGES");
                }

                System.out.println("login from user " + userHash);
                System.out.println("Delivering " + messagesForClient.size() + " message(s)...");

                String keyMessage = null;
                int signatureSize = 0;
                byte[] signatureMessage = null;
                String concatMessage = null;

                while (true) {
                    String message = dis.readUTF();
                    if ("KEY".equals(message)) {
                        message = dis.readUTF();
                        keyMessage = message;
                    }

                    if ("LENGTH".equals(message)) {
                        message = dis.readUTF();
                        signatureSize = Integer.parseInt(message);
                    }

                    if ("SIGNATURE".equals(message)) {
                        byte[] signature = new byte[signatureSize];
                        dis.readFully(signature);
                        signatureMessage = signature;
                    }

                    if ("MESSAGE".equals(message)) {
                        message = dis.readUTF();
                        concatMessage = message;
                    }

                    if ("END_MESSAGE".equals(message)) {
                        break;
                    }
                }

                // the message gets decrypted before going into the function that logs the message which
                // should encrypt the message with the corresponding public key according to the toUser
                try {
                    String userId = new String(serverCipherDecrypt.doFinal(Base64.getDecoder().decode(keyMessage)));
                    String fileName = userId + ".pub";
                    String publicKeyPath = dir + "\\" + fileName;
                    byte[] publicKeyBytes = null;
                    boolean fileExistsCheck = true;

                    try {
                        File file = new File(publicKeyPath);
                        publicKeyBytes = Files.readAllBytes(file.toPath());
                    } catch (FileNotFoundException ex) {
                        System.err.println("File for the userId has not been found, message discarded");
                        fileExistsCheck = false;
                    }

                    boolean result = verifySignature(concatMessage, signatureMessage, publicKeyBytes);

                    if (!result) {
                        System.err.println("Verification of signature failed, message discarded");
                    }

                    String[] splitMessage = concatMessage.split(",");
                    String encryptedRecipient = splitMessage[0];
                    String encryptedMessage = splitMessage[1];

                    if (fileExistsCheck && result) {
                        String decryptedToUser = new String(serverCipherDecrypt.doFinal(Base64.getDecoder().decode(encryptedRecipient)));
                        String decryptedMessage = new String(serverCipherDecrypt.doFinal(Base64.getDecoder().decode(encryptedMessage)));
                        LogMessage(decryptedToUser, userId, decryptedMessage);
                    }
                } catch (BadPaddingException ex) {
                    System.err.println("Decryption failed using the server key, message discarded");
                }

            } catch (SocketException ex) {
                System.out.println("Client disconnected...\n");
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static PrivateKey GetServerPrivateKey(String serverPrivateKeyPath) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        // This function is responsible for getting the private key for the server

        File privateFile = new File(serverPrivateKeyPath);
        FileInputStream fileInputStream = new FileInputStream(privateFile);
        byte[] serverPrivateBytes = new byte[(int) privateFile.length()];
        fileInputStream.read(serverPrivateBytes);
        fileInputStream.close();

        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(serverPrivateBytes);
        KeyFactory serverPrivateKeyFactory = KeyFactory.getInstance("RSA");

        return serverPrivateKeyFactory.generatePrivate(privateSpec);
    }

    public static void LogMessage(String toUser, String fromUser, String message) throws NoSuchAlgorithmException,
            IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        // function to log the message in the console and save it into the Message array

        // Format of the message is: toUser, fromUser, message, timestamp
        // this means that to get the message to the user, we must access message[userId] in a for loop

        // gets the public key based on the username that the message is directed to
        String fileName = toUser + ".pub";
        String dir = System.getProperty("user.dir");
        String publicKeyPath = dir + "\\" + fileName;
        FileInputStream fileInputStream;
        byte[] publicKeyBytes;

        try {
            File publicFile = new File(publicKeyPath);
            fileInputStream = new FileInputStream(publicFile);
            publicKeyBytes = new byte[(int) publicFile.length()];
            fileInputStream.read(publicKeyBytes);
            fileInputStream.close();
        } catch (FileNotFoundException ex) {
            System.err.println("The recipient UserId is not found on this server, message discarded");
            return;
        }

        // Generate the public key
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = publicKeyFactory.generatePublic(publicSpec);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        // Encrypt data
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        String timestamp = LocalDateTime.now().format(formatter);

        try {
            String fromUserEncrypted = Base64.getEncoder().encodeToString(cipher.doFinal(fromUser.getBytes()));
            String messageEncrypted = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
            String timestampEncrypted = Base64.getEncoder().encodeToString(cipher.doFinal(timestamp.getBytes()));

            String userIdHashed = GetHash(toUser);

            Messages.add(new String[]{userIdHashed, fromUserEncrypted,
                    messageEncrypted, timestampEncrypted});

            System.out.println();
            System.out.println("incoming message from " + fromUser);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("recipient: " + toUser);
            System.out.println("message: " + message + "\n");
        } catch (BadPaddingException ex) {
            System.err.println("Encryption failed, message discarded");
        }
    }

    public static List<String[]> GetMessageForUser(String userId) {
        /*
            this is responsible for returning messages to the user that is passed as a parameter
         */
        List<String[]> userMessages = new ArrayList<>();

        // this means that we are returning a message dedicated to the user userId
        Iterator<String[]> iterator = Messages.iterator();
        while(iterator.hasNext()) {
            String[] message = iterator.next();
            if(message[0].equals(userId)) {
                userMessages.add(message);
                iterator.remove(); // Removes the current element safely e.g. the message that is being returned
            }
        }

        return userMessages;
    }

    public static String GetHash(String userId) throws NoSuchAlgorithmException {
        // creates and returns the hash with appended secret string

        MessageDigest md = MessageDigest.getInstance("MD5");

        String user = "gfhk2024:" + userId;

        byte[] bytes = user.getBytes();
        byte[] digest = md.digest(bytes);

        StringBuilder sb = new StringBuilder();

        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    public static boolean verifySignature(String serverEncryptedMessage, byte[] serverMessageSignature, byte[] publicKeyBytes)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(publicKeySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(pk);

        signature.update(serverEncryptedMessage.getBytes());

        return signature.verify(serverMessageSignature);
    }
}
