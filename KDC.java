import javax.crypto.SecretKey;
import javax.security.cert.CertificateException;
import java.net.*;
import java.io.*;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
public class KDC
{
    //initialize socket and input stream
    public PublicKey pubKDC =null;
    private Socket          socket   = null;
    private ServerSocket    server   = null;
    private DataInputStream in       =  null;
    private BufferedReader br = null;
    private PrintWriter pw = null;
    private DataOutputStream out = null;
    private String clientPasswd = "";
    public static SecretKey sk = null;
    PrintWriter writer = new PrintWriter(new File("KDC_Log.txt"));
    byte[] signature_KDC;
    byte[] signature_client;
    byte[] signature_web;
    byte[] signature_mail;
    byte[] signature_database;
    // constructor with port
    public KDC(int port,boolean isFirst) throws IOException {
        // starts server and waits for a connection
        try
        {
            server = new ServerSocket(port);
            System.out.println("Server started");
            System.out.println("Waiting for a client ...");
            if(isFirst) {
                Commands commands = new Commands();
                //Burdaki adresleri DEV'e göre ayarla.
                commands.GenerateKey(System.getProperty("user.dir") + "/kdc.jks");
                commands.GenerateKey(System.getProperty("user.dir") + "/client.jks");
                commands.GenerateKey(System.getProperty("user.dir") + "/Web.jks");
                commands.GenerateKey(System.getProperty("user.dir") + "/Mail.jks");
                commands.GenerateKey(System.getProperty("user.dir") + "/Database.jks");
                clientPasswd = generatePassword();
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+clientPasswd);
                writer.flush();
                getSHA(clientPasswd, writer);
                commands.GenerateCert(System.getProperty("user.dir") + "/kdc.jks", System.getProperty("user.dir") + "/kdc.cert");
                commands.GenerateCert(System.getProperty("user.dir") + "/client.jks", System.getProperty("user.dir") + "/client.cert");
                commands.GenerateCert(System.getProperty("user.dir") + "/Web.jks", System.getProperty("user.dir") + "/Web.cert");
                commands.GenerateCert(System.getProperty("user.dir") + "/Mail.jks", System.getProperty("user.dir") + "/Mail.cert");
                commands.GenerateCert(System.getProperty("user.dir") + "/Database.jks", System.getProperty("user.dir") + "/Database.cert");
                /// Public Ke Generation
                signature_client = Commands.Create_Digital_Signature(System.getProperty("user.dir") + "/client.cert"
                        ,commands.getPrivateKey(System.getProperty("user.dir") + "/kdc.jks"));
                signature_web = Commands.Create_Digital_Signature(System.getProperty("user.dir") + "/Web.cert"
                        ,commands.getPrivateKey(System.getProperty("user.dir") + "/kdc.jks"));
                signature_mail = Commands.Create_Digital_Signature(System.getProperty("user.dir") + "/Mail.cert"
                        ,commands.getPrivateKey(System.getProperty("user.dir") + "/kdc.jks"));
                signature_database = Commands.Create_Digital_Signature(System.getProperty("user.dir") + "/Database.cert"
                        ,commands.getPrivateKey(System.getProperty("user.dir") + "/kdc.jks"));
                // Signatures generated
                pubKDC = commands.getPublicKey(System.getProperty("user.dir") + "/kdc.cert");
                System.out.println("Now you can use your keys and password from KDC_Log.txt");
            }
            Commands commands1 = new Commands();
            socket = server.accept();
            //System.out.println("Client accepted");
            // takes input from the client socket
            //Step 1 başı
            in = new DataInputStream(
                    new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());
            boolean notAuth = true;
            while(notAuth){
                String step1 = in.readUTF();
                String step0 =step1;
                step1 = commands1.DecryptRSA(step1,System.getProperty("user.dir") + "/kdc.jks");
                String[] parts = step1.split(",");
                String clientId = parts[0];
                String passwd = parts[1];
                String serverID = parts[2];
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Alice->KDC : "+step0);
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Message Decrypted : "+clientId+" , "+passwd+" , "+serverID+" , "+parts[3]);
                writer.flush();
                if(passwd.equals(this.clientPasswd)){
                    notAuth = false;
                    writer.println( DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+"KDC->Alice : Password Verified");
                    writer.flush();
                    System.out.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Authentication Successful. Password is correct");
                    out.writeUTF("1");
                    String sessionKey = commands1.generateSessionKey();
                    sk = commands1.getSessionKey(sessionKey);
                    PublicKey pubClient = commands1.getPublicKey(System.getProperty("user.dir") + "/client.cert");
                    PublicKey pubServer = commands1.getPublicKey(System.getProperty("user.dir") + "/"+serverID+".cert");
                    String ts2 = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now());
                    out.writeUTF(commands1.EncryptRSA(sessionKey+","+serverID+","+ts2,pubClient));
                    out.writeUTF(commands1.EncryptRSA("Alice"+","+serverID+","+ts2+","+sessionKey,pubServer));
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Message Decrypted : Alice , "+sessionKey+" , "+serverID+" , "+DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now()));
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" KDC->Alice : "+commands1.EncryptRSA(sessionKey+","+serverID+","+ts2,pubClient)+" , "+commands1.EncryptRSA("Alice"+","+serverID+","+ts2+","+sessionKey,pubServer));
                    writer.println(commands1.EncryptRSA("Alice"+","+serverID+","+ts2+","+sessionKey,pubServer));
                    writer.flush();
                }
                else{
                    writer.println( DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+"KDC->Alice : Password Denied");
                    writer.flush();
                    System.out.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Authentication Failed. Password is not correct");
                    out.writeUTF("0");
                }
            }
            ///Step 1 sonu
            //out.writeUTF(clientPasswd);
            // reads message from client until "Over" is sent
            //System.out.println("Closing connection");
            // close connection
            //out.close();
            System.exit(0);
        }
        catch(IOException | InterruptedException i)
        {
            System.out.println(i);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public String generatePassword() {
        int length = 8;
        String capitalCaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerCaseLetters = "abcdefghijklmnopqrstuvwxyz";
        String numbers = "1234567890";
        String combinedChars = capitalCaseLetters + lowerCaseLetters + numbers;
        SecureRandom random = new SecureRandom();
        char[] password = new char[length];
        password[0] = lowerCaseLetters.charAt(random.nextInt(lowerCaseLetters.length()));
        password[1] = capitalCaseLetters.charAt(random.nextInt(capitalCaseLetters.length()));
        password[2] = numbers.charAt(random.nextInt(numbers.length()));
        for(int i = 3; i< length ; i++) {
            password[i] = combinedChars.charAt(random.nextInt(combinedChars.length()));
        }
        String s =new String(password);
        return s;
    }
    public static void getSHA(String input,PrintWriter writer) throws NoSuchAlgorithmException, IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] messageDigest = md.digest(input.getBytes());
        //writer.println(Base64.getEncoder().encodeToString(messageDigest));
        //writer.flush();
    }
    public static void main(String args[]) throws IOException {
        KDC kdc = new KDC(3000,true);
    }
}
