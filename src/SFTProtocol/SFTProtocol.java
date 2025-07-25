package SFTProtocol;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;

public class SFTProtocol {
    private static final String RSA_ALGORITHM = "RSA";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int CHUNK_SIZE = 200;

    public static void main(String[] args) throws Exception {
        System.out.println("[SFTProtocol] Generating RSA key pairs for Alice and Bob...");

        KeyPair aliceSignPair = generateRSAKeyPair();
        saveKeyToFile("alice_sign_priv.key", aliceSignPair.getPrivate().getEncoded());
        saveKeyToFile("alice_sign_pub.key", aliceSignPair.getPublic().getEncoded());

        KeyPair aliceEncryptPair = generateRSAKeyPair();
        saveKeyToFile("alice_encryp_priv.key", aliceEncryptPair.getPrivate().getEncoded());
        saveKeyToFile("alice_encryp_pub.key", aliceEncryptPair.getPublic().getEncoded());

        KeyPair bobSignPair = generateRSAKeyPair();
        saveKeyToFile("bob_sign_priv.key", bobSignPair.getPrivate().getEncoded());
        saveKeyToFile("bob_sign_pub.key", bobSignPair.getPublic().getEncoded());

        KeyPair bobEncryptPair = generateRSAKeyPair();
        saveKeyToFile("bob_encryp_priv.key", bobEncryptPair.getPrivate().getEncoded());
        saveKeyToFile("bob_encryp_pub.key", bobEncryptPair.getPublic().getEncoded());

        System.out.println("[SFTProtocol] All keys generated and saved successfully!");
    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private static void saveKeyToFile(String fileName, byte[] key) throws IOException {
        Files.write(Paths.get(fileName), key);
        System.out.println("[SFTProtocol] Saved key: " + fileName);
    }

    public static byte[] packagePayload(String messageBase64, byte[] messageHashBytes) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] messageBytes = messageBase64.getBytes("UTF-8");
        outputStream.write(ByteBuffer.allocate(4).putInt(messageBytes.length).array());
        outputStream.write(messageBytes);
        outputStream.write(ByteBuffer.allocate(4).putInt(messageHashBytes.length).array());
        outputStream.write(messageHashBytes);
        return outputStream.toByteArray();
    }

    public static Object[] unpackagePayload(byte[] payload) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int messageLength = buffer.getInt();
        byte[] messageBytes = new byte[messageLength];
        buffer.get(messageBytes);
        String messageBase64 = new String(messageBytes, "UTF-8");
        int hashLength = buffer.getInt();
        byte[] hashBytes = new byte[hashLength];
        buffer.get(hashBytes);
        return new Object[]{messageBase64, hashBytes};
    }

    public static byte[] signFile(PrivateKey privateKey, String filePath) throws Exception {
        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initSign(privateKey);
        try (FileInputStream inputStream = new FileInputStream(filePath)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
            }
        }
        byte[] sig = signature.sign();
        System.out.println("\n----------------------------------------");
        System.out.println("[SignFile] File signed. Signature (hex): " + bytesToHex(sig));
        return sig;
    }

    public static boolean verifyFile(PublicKey publicKey, String filePath, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initVerify(publicKey);
        try (FileInputStream inputStream = new FileInputStream(filePath)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
            }
        }
        boolean result = signature.verify(signatureBytes);
        System.out.println("\n[VerifyFile] Signature verified: " + result +"\n");
        return result;
    }

    public static void encryptFile(PublicKey publicKey, String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[CHUNK_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {

                System.out.println("\n--------------------------------------");
                System.out.println("[EncryptFile] Before encrypt: " + new String(buffer, 0, bytesRead, "UTF-8"));

                byte[] encryptedChunk = cipher.doFinal(buffer, 0, bytesRead);

                System.out.println("\n[EncryptFile] After encrypt (hex): " + bytesToHex(encryptedChunk));
                System.out.println("--------------------------------------\n");

                fos.write((encryptedChunk.length >> 8) & 0xFF);
                fos.write(encryptedChunk.length & 0xFF);
                fos.write(encryptedChunk);
            }
        }
    }

    public static void decryptFile(PrivateKey privateKey, String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] sizeBytes = new byte[2];
            while (fis.read(sizeBytes) == 2) {
                int chunkSize = ((sizeBytes[0] & 0xFF) << 8) | (sizeBytes[1] & 0xFF);
                byte[] encryptedChunk = new byte[chunkSize];
                int totalRead = 0;
                while (totalRead < chunkSize) {
                    int bytesRead = fis.read(encryptedChunk, totalRead, chunkSize - totalRead);
                    if (bytesRead == -1) throw new IOException("Unexpected end of stream");
                    totalRead += bytesRead;
                }
                System.out.println("\n--------------------------------------");
                System.out.println("[DecryptFile] Before decrypt (hex): " + bytesToHex(encryptedChunk));
                byte[] decryptedChunk = cipher.doFinal(encryptedChunk);
                System.out.println("\n[DecryptFile] After decrypt: " + new String(decryptedChunk, "UTF-8"));
                System.out.println("--------------------------------------\n");
                fos.write(decryptedChunk);
            }
        }
    }

    public static PublicKey loadPublicKey(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        return kf.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        return kf.generatePrivate(spec);
    }

    public static boolean verifyFileEquality(String file1, String file2) throws IOException {
        byte[] content1 = Files.readAllBytes(Paths.get(file1));
        byte[] content2 = Files.readAllBytes(Paths.get(file2));
        return MessageDigest.isEqual(content1, content2);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
