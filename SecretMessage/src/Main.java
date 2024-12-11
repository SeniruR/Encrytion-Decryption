import java.io.File;
import java.util.Scanner;


public class Main{
    public static void main(String[] args) throws Exception {

        try {
            File keysFile = new File(CryptoUtils.myKeysFilePath);
            if (!keysFile.exists()) {
                File myPublicKeyFile = new File("myPublicKey.txt");
                if (!myPublicKeyFile.exists()) {
                    if(!myPublicKeyFile.createNewFile()){
                        System.out.println("Could not create myPublicKey file");
                        System.exit(1);
                    }
                }
                if(keysFile.createNewFile())
                    CryptoUtils.generateAndStoreAsymmetricKeys();
            }
        } catch (Exception e) {
            System.err.println("Failed to locate or create 'keys.txt': " + e.getMessage());
            System.exit(1);
        }

        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\nMenu:");
            System.out.println("1. Generate a new asymmetric key pair.");
            System.out.println("2. Encrypt a message and create the 'encrypted.txt' file");
            System.out.println("3. Decrypt the given file and verify integrity");
            System.out.println("4. Exit");
            System.out.print("Choose an option: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline character

            switch (choice) {
                case 1:
                    CryptoUtils.generateAndStoreAsymmetricKeys();
                    break;
                case 2:
                    System.out.println("Enter the message to encrypt : ");
                    String message = scanner.nextLine();
                    System.out.println("Enter the name of the public key file of the receiver \n(Hint : Request the publicKey.txt file from the receiver, rename it with the receivers name, place it in the 'myContacts' Folder and provide the given name without .txt here) : ");
                    String othersPublicKeyPath = scanner.nextLine();
                    System.out.println("Enter the name of the file that the encoded message should be saved (Eg : Message1) : ");
                    String outputFileName = scanner.nextLine();
                    try{
                        CryptoUtils.encryptAndSaveToFile(message, othersPublicKeyPath, outputFileName);
                        System.out.println("Message encrypted successfully\nFind the '" + outputFileName + ".txt' in 'Send' folder and Send it to the receiver");
                    } catch (Exception e){
                        System.err.println("An error occurred.\n" + e.getMessage());
                    }
                    break;
                case 3:
                    System.out.println("Place the encrypted message txt file you received in the 'Receive' Folder and Enter the name of it.");
                    String encryptedMessageFileName = scanner.nextLine();
                    System.out.println("Enter the public key file name of the sender  \n(Hint : Request the publicKey.txt file from the sender, rename it with the sender's name, place it in the 'myContacts' Folder and provide the given name without .txt here) : ");
                    String senderPubKeyFileName = scanner.nextLine();
                    try{
                        System.out.println(CryptoUtils.decryptAndVerify(encryptedMessageFileName, senderPubKeyFileName));
                    }catch (Exception e){
                        System.err.println("An error occurred.\n" + e.getMessage());
                    }
                    break;
                case 4:
                    System.out.println("Exiting program...");
                    scanner.close();
                    return;
                default:
                    System.out.println("Wrong Input");
            }
        }
    }
}