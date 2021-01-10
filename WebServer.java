
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class WebServer
{
    //initialize socket and input stream
    private Socket          socket   = null;
    private ServerSocket    server   = null;
    private DataInputStream in       =  null;
    private DataOutputStream out = null;
    PrintWriter writer = new PrintWriter(new File("Web_Log.txt"));
    // constructor with port
    public WebServer(int port) throws FileNotFoundException {
        // starts server and waits for a connection
        try
        {
            Commands commands = new Commands();
            server = new ServerSocket(port);


            socket = server.accept();


            // takes input from the client socket
            in = new DataInputStream(
                    new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());


            String nonceO = String.valueOf(commands.generateNonce());
            String step3 = in.readUTF();
            String [] parts = step3.split(",");
            String t = commands.util();
            t = commands.DecryptRSA(t,System.getProperty("user.dir") + "/Web.jks");
            String [] parts2 = t.split(",");
            writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Alice->Web : "+"Alice , "+commands.util()+" , "+parts2[3]);
            writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Ticket Decrpyted : "+t);
            writer.flush();
            String nonce = commands.decrypt(parts[2],commands.getSessionKey(parts2[3]));
            writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Message Decrpyted : N1="+nonce);
            writer.flush();
            writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Web->Alice : "+String.valueOf(Integer.parseInt(nonce)+1)+" , "+nonceO);
            writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Web->Alice : "+commands.encrypt(String.valueOf(Integer.parseInt(nonce)+1)+","+nonceO,commands.getSessionKey(parts2[3])));
            writer.flush();
            out.writeUTF(commands.encrypt(String.valueOf(Integer.parseInt(nonce)+1)+","+nonceO,commands.getSessionKey(parts2[3])));
            String step5 = in.readUTF();
            writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Alice->Web : "+step5);
            step5 = commands.decrypt(step5,commands.getSessionKey(parts2[3]));
            writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Message Decrpyted : "+step5);
            writer.flush();
            if(step5.equals(String.valueOf(Integer.parseInt(nonceO)+1))){
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Web->Alice : Authentication is completed!");
                writer.flush();
                out.writeUTF("1");
            }
            else{
                writer.println(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss").format(LocalDateTime.now())+" Web->Alice : Authetication is failed");
                writer.flush();
                out.writeUTF("0");
            }
            // reads message from client until "Over" is sent

        }
        catch(IOException i)
        {
            System.out.println(i);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public WebServer() throws FileNotFoundException {
    }

    public static void main(String args[]) throws FileNotFoundException {

        WebServer ms = new WebServer(3001);

    }
}

