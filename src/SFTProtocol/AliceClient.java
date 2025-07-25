package SFTProtocol;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;

public class AliceClient {

    private static final String HOST = "localhost";
    private static final int PORT = 5000;
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    public static void main(String[] args) {
        try {
            // Load Alice's private keys
            PrivateKey aliceSignPriv = SFTProtocol.loadPrivateKey("alice_sign_priv.key");
            PrivateKey aliceEncryptPriv = SFTProtocol.loadPrivateKey("alice_encryp_priv.key");

            // Load Bob's public keys
            PublicKey bobEncryptPub = SFTProtocol.loadPublicKey("bob_encryp_pub.key");
            PublicKey bobSignPub = SFTProtocol.loadPublicKey("bob_sign_pub.key");

            System.out.println("[Alice] Keys loaded from files.");

            Socket socket = new Socket(HOST, PORT);
            System.out.println("\n > [Alice] Connected to Bob.");

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // ===================================================================================
            // Step 1: Send signed request
            // ===================================================================================
            String request = "Request for a File!";
            byte[] requestBytes = request.getBytes(StandardCharsets.UTF_8);

            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initSign(aliceSignPriv);
            signature.update(requestBytes);
            byte[] signedRequest = signature.sign();

            System.out.println("\n----------------------------------------");
            System.out.println("Before sign (request): " + request);
            System.out.println("\nAfter sign (hex): " + SFTProtocol.bytesToHex(signedRequest));
            System.out.println("----------------------------------------\n");

            out.writeObject(requestBytes);
            out.writeObject(signedRequest);
            out.flush();
            System.out.println(" > [Alice] Sent signed request.\n");

            // ===================================================================================
            // Step 2: Receive Bob's signed timestamp
            // ===================================================================================
            byte[] encTimestamp = (byte[]) in.readObject();
            byte[] bobTimestampSig = (byte[]) in.readObject();

            System.out.println(" > [Alice] Received Response.");

            System.out.println("\n----------------------------------------");
            System.out.println("Encrypted timestamp (hex): " + SFTProtocol.bytesToHex(encTimestamp));

            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, aliceEncryptPriv);
            byte[] timestampBytes = cipher.doFinal(encTimestamp);
            String timestamp = new String(timestampBytes, StandardCharsets.UTF_8);

            System.out.println("\nDecrypted timestamp: " + timestamp);

            Signature sigVerify = Signature.getInstance(SIGN_ALGORITHM);
            sigVerify.initVerify(bobSignPub);
            sigVerify.update(timestampBytes);
            boolean verified = sigVerify.verify(bobTimestampSig);

            System.out.println("\nVerified timestamp signature? " + verified);
            System.out.println("----------------------------------------\n");

            // ===================================================================================
            // Step 3: Send secure file name with hash
            // ===================================================================================
            String fileName = "TopSecret.txt";
            byte[] fileNameBytes = fileName.getBytes(StandardCharsets.UTF_8);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fileNameBytes);

            byte[] payload = SFTProtocol.packagePayload(fileName, hash);

            signature.initSign(aliceSignPriv);
            signature.update(payload);
            byte[] signedPayload = signature.sign();

            cipher.init(Cipher.ENCRYPT_MODE, bobEncryptPub);

            System.out.println("----------------------------------------");
            System.out.println("Before encrypt (payload): " + SFTProtocol.bytesToHex(payload));

            byte[] encPayload = cipher.doFinal(payload);

            System.out.println("\nAfter encrypt (payload hex): " + SFTProtocol.bytesToHex(encPayload));
            System.out.println("\nAfter sign (payload hex): " + SFTProtocol.bytesToHex(signedPayload));
            System.out.println("----------------------------------------\n");

            out.writeObject(encPayload);
            out.writeObject(signedPayload);
            out.flush();

            System.out.println(" > [Alice] Sent encrypted filename with hash.\n");

            // ===================================================================================
            // Step 4: Receive file signature from Bob
            // ===================================================================================
            byte[] fileSig = (byte[]) in.readObject();

            System.out.println(" > [Alice] Received file signature.\n");

            System.out.println("----------------------------------------");
            System.out.println("Received file signature: " + SFTProtocol.bytesToHex(fileSig));
            System.out.println("----------------------------------------\n");

            // ===================================================================================
            // Step 5: Receive encrypted file from Bob
            // ===================================================================================
            String encryptedFile = "Received_file.enc";
            receiveFile(encryptedFile, in);
            System.out.println("\n > [Alice] Encrypted file received: " + encryptedFile);

            // ===================================================================================
            // Step 6: Decrypt file
            // ===================================================================================
            String decryptedFile = "Received_file.txt";
            SFTProtocol.decryptFile(aliceEncryptPriv, encryptedFile, decryptedFile);
            System.out.println(" > [Alice] File decrypted: " + decryptedFile);

            // ===================================================================================
            // Step 7: Verify file signature
            // ===================================================================================
            boolean fileVerified = SFTProtocol.verifyFile(bobSignPub, decryptedFile, fileSig);
            System.out.println(" > [Alice] File signature verified? " + fileVerified);

            socket.close();
            System.out.println(" > [Alice] Connection closed.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void receiveFile(String path, ObjectInputStream in) throws IOException, ClassNotFoundException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            Object obj;
            while ((obj = in.readObject()) != null) {
                byte[] chunk = (byte[]) obj;
                System.out.println(" > [Alice] Receiving file chunk (size): " + chunk.length);
                fos.write(chunk);
            }
        } catch (EOFException ignored) {
        }
    }
}
