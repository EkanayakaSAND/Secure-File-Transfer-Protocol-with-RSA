package SFTProtocol;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import java.util.Arrays;

public class BobServer {

    private static final int PORT = 5000;
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    public static void main(String[] args) {
        try {
            // Load Bob's private keys
            PrivateKey bobSignPriv = SFTProtocol.loadPrivateKey("bob_sign_priv.key");
            PrivateKey bobEncryptPriv = SFTProtocol.loadPrivateKey("bob_encryp_priv.key");

            // Load Alice's public keys
            PublicKey aliceSignPub = SFTProtocol.loadPublicKey("alice_sign_pub.key");
            PublicKey aliceEncryptPub = SFTProtocol.loadPublicKey("alice_encryp_pub.key");

            System.out.println("[Bob] Keys loaded from files.");

            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("\n > [Bob] Waiting for Alice...");
            Socket socket = serverSocket.accept();
            System.out.println(" > [Bob] Alice connected.");

            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

            // ===================================================================================
            // Step 1: Receive Alice's signed request
            // ===================================================================================
            byte[] requestBytes = (byte[]) in.readObject();
            byte[] signedRequest = (byte[]) in.readObject();

            System.out.println("\n----------------------------------------");
            System.out.println("Raw Received Request (bytes): " + SFTProtocol.bytesToHex(requestBytes));
            System.out.println("\nReceived Signature (bytes): " + SFTProtocol.bytesToHex(signedRequest));

            Signature sigVerify = Signature.getInstance(SIGN_ALGORITHM);
            sigVerify.initVerify(aliceSignPub);
            sigVerify.update(requestBytes);
            boolean verified = sigVerify.verify(signedRequest);
            String request = new String(requestBytes, StandardCharsets.UTF_8);

            System.out.println("\nRequest after decryption: " + request);
            System.out.println("\nSignature Verified? " + verified);
            System.out.println("----------------------------------------\n");

            // ===================================================================================
            // Step 2: Send signed timestamp
            // ===================================================================================
            byte[] timestampBytes = java.time.Instant.now().toString().getBytes(StandardCharsets.UTF_8);

            System.out.println("----------------------------------------");
            System.out.println("Timestamp before sign: " + new String(timestampBytes, StandardCharsets.UTF_8));

            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initSign(bobSignPriv);
            signature.update(timestampBytes);
            byte[] bobTimestampSig = signature.sign();

            System.out.println("\nTimestamp signature (hex): " + SFTProtocol.bytesToHex(bobTimestampSig));

            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, aliceEncryptPub);
            byte[] encTimestamp = cipher.doFinal(timestampBytes);

            System.out.println("\nTimestamp after encryption (hex): " + SFTProtocol.bytesToHex(encTimestamp));
            System.out.println("----------------------------------------\n");

            out.writeObject(encTimestamp);
            out.writeObject(bobTimestampSig);
            out.flush();
            System.out.println(" > [Bob] Sent encrypted timestamp and signature.");

            // ===================================================================================
            // Step 3: Receive secure file name with hash
            // ===================================================================================
            byte[] encPayload = (byte[]) in.readObject();
            byte[] signedPayload = (byte[]) in.readObject();

            System.out.println("\n > [Bob] Received Encrypted Payload.");

            System.out.println("\n----------------------------------------");
            System.out.println("Encrypted Payload (hex): " + SFTProtocol.bytesToHex(encPayload));
            System.out.println("\nSigned Payload (hex): " + SFTProtocol.bytesToHex(signedPayload));

            cipher.init(Cipher.DECRYPT_MODE, bobEncryptPriv);
            byte[] payload = cipher.doFinal(encPayload);

            System.out.println("\nPayload after decryption (hex): " + SFTProtocol.bytesToHex(payload));

            sigVerify.initVerify(aliceSignPub);
            sigVerify.update(payload);
            verified = sigVerify.verify(signedPayload);
            System.out.println("\nPayload signature verified? " + verified);

            Object[] unpacked = SFTProtocol.unpackagePayload(payload);
            String fileName = (String) unpacked[0];
            byte[] fileHash = (byte[]) unpacked[1];

            System.out.println("\nFile requested by Alice: " + fileName);
            System.out.println("----------------------------------------\n");

            // ===================================================================================
            // Step 4: Bob SENDS the file to Alice
            // ===================================================================================
            System.out.println("\n > [Bob] Preparing to send file to Alice...");

            // Sign original file
            byte[] fileSig = SFTProtocol.signFile(bobSignPriv, fileName);

            // Encrypt file with Alice's public key
            String encryptedFile = fileName + ".enc";
            SFTProtocol.encryptFile(aliceEncryptPub, fileName, encryptedFile);

            // Send file signature first
            System.out.println(" > [Bob] Sending file signature.");

            System.out.println("\n----------------------------------------");
            System.out.println("Sending file signature: " + SFTProtocol.bytesToHex(fileSig));
            System.out.println("----------------------------------------\n");

            out.writeObject(fileSig);
            out.flush();

            // Send encrypted file
            sendFile(encryptedFile, out);
            System.out.println("\n > [Bob] Sent encrypted file: " + encryptedFile);

            // Close all
            socket.close();
            serverSocket.close();
            System.out.println(" > [Bob] Connection closed.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendFile(String path, ObjectOutputStream out) throws IOException {
        try (FileInputStream fis = new FileInputStream(path)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                System.out.println(" > [Bob] Sending file chunk (size): " + bytesRead);
                out.writeObject(Arrays.copyOf(buffer, bytesRead));
            }
        }
        out.writeObject(null); // indicate end of file
    }
}
