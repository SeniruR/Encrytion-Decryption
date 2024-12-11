import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {

    public static final String myKeysFilePath = "keys.txt";

    // Generate asymmetric key pair and store in a txt file
    public static void generateAndStoreAsymmetricKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        String PublicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());

        try (FileWriter writer = new FileWriter(myKeysFilePath)) {
            writer.write("Public Key: " + PublicKey + "\n");
            writer.write("Private Key: " + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) + "\n");
            try (FileWriter publicKeyWriter = new FileWriter("myPublicKey.txt")) {
                publicKeyWriter.write("Public Key: " + PublicKey + "\n");
            }
            System.out.println("New key generated and stored successfully\n");
            System.out.println("Find the 'myPublicKey.txt' file in the root directory, rename it with your name and send it to the sender you wish to receive message from.");
        }
        catch (Exception e) {
            System.err.println("Failed to generate and store the AsymmetricKeys\n" + e.getMessage());
        }
    }

    // Generate a symmetric key
    public static SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // Encrypt message, hash, and symmetric key
    public static void encryptAndSaveToFile(String message, String recipientPubKeyFileName, String outputFileName) throws Exception {

        SecretKey symKey = generateSymmetricKey();

        BufferedReader othersPublicKeyTxt = new BufferedReader(new FileReader("myContacts/" + recipientPubKeyFileName + ".txt"));
        PublicKey recipientPubKey = stringToPublicKey(othersPublicKeyTxt.readLine().split(": ")[1]);
        othersPublicKeyTxt.close();

        BufferedReader myKeysTxt = new BufferedReader(new FileReader(myKeysFilePath));
        String myPublicKeyString =  myKeysTxt.readLine().split(": ")[1];
        PrivateKey senderPrivateKey = stringToPrivateKey(myKeysTxt.readLine().split(": ")[1]);
        myKeysTxt.close();

        // Encrypt message with symmetric key
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, symKey);
        byte[] encryptedMessage = aesCipher.doFinal(message.getBytes());

        // Hash the message and encrypt with private key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = sha256.digest(message.getBytes());

        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, senderPrivateKey);
        byte[] encryptedHash = rsaCipher.doFinal(messageHash);

        // Encrypt symmetric key with public key
        rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPubKey);
        byte[] encryptedSymKey = rsaCipher.doFinal(symKey.getEncoded());

        File file = new File("Send/" + outputFileName + ".txt");
        if(file.exists()) {
            System.out.println("Output file already exists!");
            return;
        }

        if(file.createNewFile()){
            try (FileWriter writer = new FileWriter("Send/" + outputFileName + ".txt")) {
                writer.write(Base64.getEncoder().encodeToString(encryptedMessage) + "\n");
                writer.write(Base64.getEncoder().encodeToString(encryptedHash) + "\n");
                writer.write(Base64.getEncoder().encodeToString(encryptedSymKey) + "\n");
            }
        }else {
            System.err.println("Output file creation failed!");
        }

    }

    // Decrypt file and verify integrity
    public static String decryptAndVerify(String encryptedMessageFileName, String sendersPublicKeyFileName) throws Exception {
        PublicKey senderPubKey = null;
        PrivateKey recipientPrivateKey = null;
        String encryptedMessage = null, encryptedHash = null, encryptedSymKey = null;

        // Handle sender's public key file
        try (BufferedReader othersPublicKeyTxt = new BufferedReader(new FileReader("myContacts/" + sendersPublicKeyFileName + ".txt"))) {
            senderPubKey = stringToPublicKey(othersPublicKeyTxt.readLine().split(": ")[1]);
        } catch (FileNotFoundException e) {
            System.err.println("Sender's public key file not found.");
            throw e; // Re-throw to let the caller handle if needed
        } catch (Exception e) {
            System.err.println("Failed to read sender's public key: " + e.getMessage());
            throw e;
        }

        // Handle recipient's private key file
        try (BufferedReader myKeysTxt = new BufferedReader(new FileReader(myKeysFilePath))) {
            myKeysTxt.readLine(); // Skip the public key line
            recipientPrivateKey = stringToPrivateKey(myKeysTxt.readLine().split(": ")[1]);
        } catch (FileNotFoundException e) {
            System.err.println("Recipient's private key file not found: " + myKeysFilePath);
            throw e;
        } catch (Exception e) {
            System.err.println("Failed to read recipient's private key: " + e.getMessage());
            throw e;
        }

        // Handle input file
        try (BufferedReader reader = new BufferedReader(new FileReader("Receive/" + encryptedMessageFileName + ".txt"))) {
            encryptedMessage = reader.readLine();
            encryptedHash = reader.readLine();
            encryptedSymKey = reader.readLine();
        } catch (FileNotFoundException e) {
            System.err.println("Input file not found.");
            throw e;
        } catch (Exception e) {
            System.err.println("Failed to read input file: " + e.getMessage());
            throw e;
        }

        try {
            // Decrypt symmetric key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, recipientPrivateKey);
            byte[] symKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedSymKey));
            SecretKey symKey = new SecretKeySpec(symKeyBytes, "AES");

            // Decrypt message
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, symKey);
            byte[] messageBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            String message = new String(messageBytes);

            // Decrypt hash
            rsaCipher.init(Cipher.DECRYPT_MODE, senderPubKey);
            byte[] decryptedHash = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedHash));

            // Hash the message and compare
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] computedHash = sha256.digest(message.getBytes());

            System.out.println("Message : " + message);

            if (MessageDigest.isEqual(decryptedHash, computedHash)) {
                return "Integrity verified. Message is sent by " + sendersPublicKeyFileName + ".";
            } else {
                return "Warning!!!! Integrity check failed! Message is not sent by " + sendersPublicKeyFileName + ".";
            }
        } catch (Exception e) {
            // Catch decryption or verification errors
            return "Decryption or verification failed: " + e.getMessage();
        }
    }


    public static PublicKey stringToPublicKey(String sendersPublicKey) throws Exception {
        // Decode the Base64-encoded string to bytes
        byte[] keyBytes = Base64.getDecoder().decode(sendersPublicKey);

        // Create a KeyFactory for RSA keys
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Use X509EncodedKeySpec to represent the public key
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        // Generate the PublicKey object
        return keyFactory.generatePublic(spec);
    }

    public static PrivateKey stringToPrivateKey(String privateKey) throws Exception {
        // Decode the Base64-encoded string to bytes
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);

        // Create a KeyFactory for RSA keys
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Use PKCS8EncodedKeySpec to represent the private key
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        // Generate the PrivateKey object
        return keyFactory.generatePrivate(spec);
    }
}
