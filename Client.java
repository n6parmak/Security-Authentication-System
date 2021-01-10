// A Java program for a Client
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.cert.CertificateException;
import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Scanner;

public class Client
{
    // initialize socket and input output streams
    private Socket socket            = null;
    private DataInputStream  input   = null;
    private DataOutputStream out     = null;
    private DataInputStream inServer = null;
    private String clientPasswd ="";
    public SecretKey sessionKey;
    private String ticket ="";
    PrintWriter writer = new PrintWriter(new FileOutputStream(new File("Alice_Log.txt"),true));
    // constructor to put ip address and port
    public Client(String address, int port,String alice, String passwd, String serverID) throws FileNotFoundException {
        // establish a connection
        try
        {
            Commands commands = new Commands();
            socket = new Socket(address, port);
            //authenticate();
            //System.out.println("Connected");

            // takes input from terminal
            input  = new DataInputStream(System.in);

            // sends output to the socket
            out    = new DataOutputStream(socket.getOutputStream());
            inServer = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            //clientPasswd = inServer.readUTF();
            //System.out.println(clientPasswd);
            if(port == 3000) {

                PublicKey pubKDC = commands.getPublicKey(System.getProperty("user.dir") + "/kdc.cert");
                String ts1 = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now());
                String step1 = commands.EncryptRSA(alice + "," + passwd + "," + serverID + "," + ts1, pubKDC);
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->KDC : "+alice+" , "+passwd+" , "+serverID+" , "+ts1);
                writer.flush();
                out.writeUTF(step1);
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->KDC : "+alice+" , "+step1);
                writer.flush();
                String authValue = inServer.readUTF();
                while (!authValue.equals("1")) {
                    ts1 = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now());
                    Scanner in = new Scanner(System.in);
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" KDC->"+alice+" : Password Denied");
                    writer.flush();
                    System.out.println("Your Password is incorrect! Try again");
                    String pass = in.nextLine();
                    String step = commands.EncryptRSA(alice + "," + pass + "," + serverID + "," + ts1, pubKDC);
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->KDC : "+alice+" , "+pass+" , "+serverID+" , "+ts1);
                    writer.flush();
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->KDC : "+alice+" , "+step);
                    writer.flush();
                    out.writeUTF(step);
                    authValue = inServer.readUTF();
                }
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" KDC->"+alice+" : Password Verified");
                writer.flush();
                //Step 2 başlangıcı
                String step2 = inServer.readUTF();
                ticket = inServer.readUTF();
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" KDC->"+alice+" : "+step2+" , "+ticket);
                writer.flush();
                step2 = commands.DecryptRSA(step2, System.getProperty("user.dir") + "/client.jks");
                String[] parts = step2.split(",");
                String strSesKey = parts[0];
                this.sessionKey = commands.getSessionKey(strSesKey);
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Message Decrypted : "+step2);
                writer.flush();

                //Step 2 sonu
                try
                {
                    //input.close();
                    out.close();
                    socket.close();
                    return;
                }
                catch(IOException i)
                {
                    System.out.println(i);
                }

            }
            else{
                String nonce = String.valueOf(commands.generateNonce());
                String t = commands.util();
                t = commands.DecryptRSA(t,System.getProperty("user.dir") + "/"+serverID+".jks");
                String [] parts = t.split(",");
                System.out.println(parts[3]);
                out.writeUTF(alice+","+commands.util()+","+commands.encrypt(nonce,commands.getSessionKey(parts[3])));
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->"+serverID+" : "+alice+" , "+nonce);
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->"+serverID+" : "+alice+" , "+commands.util()+" , "+commands.encrypt(nonce,commands.getSessionKey(parts[3])));
                writer.flush();
                String step4 = inServer.readUTF();
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+serverID+"->"+alice+" : "+step4);
                writer.flush();
                step4 = commands.decrypt(step4,commands.getSessionKey(parts[3]));
                String [] parts4 = step4.split(",");
                String nonce4 = String.valueOf(commands.generateNonce());
                if(parts4[0].equals(String.valueOf(Integer.parseInt(nonce)+1))){
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Message Decrpyted : "+parts4[0]+" is OK, N2 = "+parts4[1]);
                    writer.flush();
                    out.writeUTF(commands.encrypt(String.valueOf(Integer.parseInt(parts4[1])+1),commands.getSessionKey(parts[3])));
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->"+serverID+" : "+String.valueOf(Integer.parseInt(parts4[1])+1));
                    writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+alice+"->"+serverID+" : "+commands.encrypt(String.valueOf(Integer.parseInt(parts4[1])+1),commands.getSessionKey(parts[3])));
                    writer.flush();
                    String auth = inServer.readUTF();
                    if(auth.equals("1")) {
                        writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+serverID+"->"+alice+" : Authentication is completed!");
                        writer.flush();
                    }
                    else{
                        writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" "+serverID+"->"+alice+" : Authentication is failed!");
                        writer.flush();
                    }
                }
                else{
                    writer.println("Nonce Value is not correct");
                    writer.flush();
                }
                System.exit(0);
            }
        }
        catch(UnknownHostException u)
        {
            System.out.println(u);
        }
        catch(IOException i)
        {
            System.out.println(i);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        // string to read message from input
        String line = "";

        // keep reading until "Over" is input
        while (!line.equals("Over"))
        {
            try
            {
                line = input.readLine();
                out.writeUTF(line);
            }
            catch(IOException i)
            {
                System.out.println(i);
            }
        }

        // close the connection
        try
        {
            input.close();
            out.close();
            socket.close();
        }
        catch(IOException i)
        {
            System.out.println(i);
        }
    }

    private void authenticate(boolean isConnected,String serverId,String clientId) {
    }


    public static void main(String args[]) throws FileNotFoundException {


        Scanner in = new Scanner(System.in);
        System.out.println("Please Enter your password");
        String passwd = in.nextLine();
        System.out.println("Please Enter your ServerID");
        String serverID = in.nextLine();
        Authenticate("Alice",passwd,serverID);


        //KDCStart();

    }

    private static void Authenticate(String alice, String passwd, String serverID) throws FileNotFoundException {
        Client client = new Client("127.0.0.1", 3000,alice,passwd,serverID);
        Client client1 = new Client("127.0.0.1", 3001,alice,passwd,serverID);

    }


}
