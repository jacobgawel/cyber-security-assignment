import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class Client {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        if (args.length != 3) {
            System.err.println("Usage: java Client host port userId");
            System.exit(-1);
        }

        System.out.println("Client program (user " + args[2] + ")");
        System.out.println("--------------");

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2]; // <------ userid variable
        // declaring filenames
        String publicFilename = args[2] + ".pub";
        String privateFilename = args[2] + ".prv";

        // get current working directory
        // TODO: For not it gets args[2].prv, args[2].pub -> alice.pub, alice.prv
        // we must get the other .pub key if it exists
        String dir = System.getProperty("user.dir");
        String publicKeyPath = dir + "\\" + publicFilename;
        String privateKeyPath = dir + "\\" + privateFilename;

        // append filename using userId ---> alice.pub, alice.prv
        // search the current directory for those filenames

        FileInputStream fis = new FileInputStream(publicKeyPath);
        byte[] publicKeyBytes = new byte[fis.available()];
        fis.read(publicKeyBytes);
        fis.close();

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

        try {
            String userHash = GetHashFromUser(args); // Assume this function exists and works as intended
            Socket socket = new Socket(host, port);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            DataInputStream dis = new DataInputStream(socket.getInputStream());

            // Send user hash first before attempting to read messages
            dos.writeUTF(userHash);

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
                serverMessage.add(message);
            }

            // Print messages received from the server
            for (String text : serverMessage) {
                System.out.println(text);
            }

            // After processing server messages, send client messages
            dos.writeUTF(userId);
            dos.writeUTF("bob"); // Assuming "bob" is the recipient
            dos.writeUTF("hello world"); // The message
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
