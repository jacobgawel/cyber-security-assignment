import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

public class Server {
    static List<String[]> Messages = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        // tries to get the port from the command line argument

        int port;
        String serverPrivateFilename = "server.prv";
        String dir = System.getProperty("user.dir");
        String serverPrivateKeyPath = dir + "\\" + serverPrivateFilename;
        if (args.length != 1) {
            System.err.println("Usage: java Server port");
            System.exit(-1);
        }

        // Getting server private key
        File srvPrivateFile = new File(serverPrivateKeyPath);
        FileInputStream serverPrivateFis = new FileInputStream(srvPrivateFile);
        byte[] serverPrivateBytes = new byte[(int) srvPrivateFile.length()];
        serverPrivateFis.read(serverPrivateBytes);
        serverPrivateFis.close();

        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(serverPrivateBytes);
        KeyFactory serverPrivateKeyFactory = KeyFactory.getInstance("RSA");
        PrivateKey serverPrivateKey = serverPrivateKeyFactory.generatePrivate(privateSpec);

        Cipher serverCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        serverCipherDecrypt.init(Cipher.DECRYPT_MODE, serverPrivateKey);

        port = Integer.parseInt(args[0]);

        ServerSocket socketServer = new ServerSocket(port);

        LogMessage("alice", "bob", "This is a test");

        System.out.println("Server program");
        System.out.println("--------------");

        while(true) {
            Socket socket = socketServer.accept();
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            String userHash = dis.readUTF();

            List<String[]> messagesForClient = GetMessageForUser(userHash);

            if(!messagesForClient.isEmpty()) {
                for (String[] message : messagesForClient) {
                    dos.writeUTF(message[1]);
                    dos.writeUTF(message[2]);
                    dos.writeUTF(message[3]);
                }
                dos.writeUTF("END_OF_SERVER_MESSAGE");
            } else {
                dos.writeUTF("NO_SERVER_MESSAGES");
            }

            System.out.println("login from user " + userHash);
            System.out.println("Delivering " + messagesForClient.size() + " message(s)...");

            List<String> clientMessage = new ArrayList<>();
            while(true) {
                String message = dis.readUTF();
                if("END_OF_CLIENT_MESSAGE".equals(message)) {
                    break;
                }
                clientMessage.add(message);
            }

            String fromUserEncrypted = clientMessage.get(0);
            String toUserEncrypted = clientMessage.get(1);
            String messageEncrypted = clientMessage.get(2);

            // the message gets decrypted before going into the function that logs the message which
            // should encrypt the message with the corresponding public key according to the toUser
            String decryptedFromUser = new String(serverCipherDecrypt.doFinal(Base64.getDecoder().decode(fromUserEncrypted)));
            String decryptedToUser = new String(serverCipherDecrypt.doFinal(Base64.getDecoder().decode(toUserEncrypted)));
            String decryptedMessage = new String(serverCipherDecrypt.doFinal(Base64.getDecoder().decode(messageEncrypted)));

            LogMessage(decryptedToUser, decryptedFromUser, decryptedMessage);
        }
    }

    public static void LogMessage(String toUser, String fromUser, String message) throws NoSuchAlgorithmException {
        /*
            this is the simple function that is supposed to add the message to the list,
            this is likely well the encryption will be implemented later on
         */

        // Format of the message is: toUser, fromUser, message, timestamp, readStatus
        // this means that to get the message to the user, we must access message[userId] in a for loop
        String userIdHashed = GetHash(toUser);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        Messages.add(new String[]{userIdHashed, fromUser, message, LocalDateTime.now().format(formatter)});
        System.out.println(LocalDateTime.now().format(formatter));
        System.out.println("incoming message from " + fromUser);
        System.out.println("recipient: " + toUser);
        System.out.println("message: " + message + "\n");
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
                iterator.remove(); // Removes the current element safely
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
}
