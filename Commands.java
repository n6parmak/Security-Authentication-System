import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.Executors;

public class Commands {

    public void GenerateKey(String privateKeyPath) throws IOException, InterruptedException {
        boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
        ProcessBuilder builder = new ProcessBuilder();

        if (isWindows) {
            builder.command("cmd.exe", "/c", "keytool -genkey -keyalg RSA -keystore " + privateKeyPath + " -keysize 2048 -dname \"CN=CA, OU=Company, O=Company, L=local, ST=Unknown, C=DK\" -keypass 123456 -validity 1 -storepass 123456");
        } else {
            builder.command("sh", "-c", "keytool -genkey -keyalg RSA -keystore " + privateKeyPath + " -keysize 2048 -dname \"CN=CA, OU=Company, O=Company, L=local, ST=Unknown, C=DK\" -keypass 123456 -validity 1 -storepass 123456");
        }
        builder.directory(new File(System.getProperty("user.home")));
        Process process = builder.start();
        final PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(process.getOutputStream())
        );
        writer.close();
        StreamGobbler streamGobbler =
                new StreamGobbler(process.getInputStream(), System.out::println);
        Executors.newSingleThreadExecutor().submit(streamGobbler);
        Thread.sleep(1000);
    }

    public void GenerateCert(String privateKeyPath, String certificatePath) throws IOException, InterruptedException {
        boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
        ProcessBuilder builder = new ProcessBuilder();
        if (isWindows) {
            builder.command("cmd.exe", "/c", "keytool -export -keystore " + privateKeyPath + " -rfc -file " + certificatePath + " -storepass 123456");

        } else {
            String dirpri = privateKeyPath.substring(privateKeyPath.indexOf("/") + 1);
            String dircert = certificatePath.substring(certificatePath.lastIndexOf("/") + 1);
            builder.command("sh", "-c", "keytool -export -keystore " + privateKeyPath + " -rfc -file " + certificatePath + " -storepass 123456");
        }
        builder.directory(new File(System.getProperty("user.dir")));
        Process process = builder.start();
        final PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(process.getOutputStream())
        );
        // writer.print("123456\n"); // These and other writer.print(...) statements
        // writer.print("123456\n");
        writer.close();
        StreamGobbler streamGobbler =
                new StreamGobbler(process.getInputStream(), System.out::println);
        Executors.newSingleThreadExecutor().submit(streamGobbler);
        Thread.sleep(1000);
    }

    public PublicKey getPublicKey(String cert) throws FileNotFoundException, CertificateException {
        FileInputStream fin = new FileInputStream(cert);
        X509Certificate certificate = X509Certificate.getInstance(fin);
        return certificate.getPublicKey();
    }

    public PrivateKey getPrivateKey(String privateKeyPath) throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, java.security.cert.CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(privateKeyPath), "123456".toCharArray());
        PrivateKey key = (PrivateKey) ks.getKey("mykey", "123456".toCharArray());
        return key;
    }

    public String EncryptRSA(String input, PublicKey pb) {
        byte[] crypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pb);
            crypted = cipher.doFinal(input.getBytes());
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();

        return new String(encoder.encodeToString(crypted));
    }

    public String DecryptRSA(String input, String privateKeyPath) {
        byte[] output = null;
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(privateKeyPath), "123456".toCharArray());
            PrivateKey key = (PrivateKey) ks.getKey("mykey", "123456".toCharArray());
            java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            output = cipher.doFinal(decoder.decode(input));
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return new String(output);
    }

    public String generateSessionKey() throws NoSuchAlgorithmException {
        // create new key
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        // get base64 encoded version of the key
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        return encodedKey;
    }

    public SecretKey getSessionKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        // rebuild key using SecretKeySpec
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }

    ////////////////SYMMETRIC KEY ENCRYPTION/DECRYPTION
    public String encrypt(String input, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher;
        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public String decrypt(String cipherText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public int generateNonce() {
        SecureRandom ranGen = new SecureRandom();
        return ranGen.nextInt(199999999);
    }

    public String util() throws IOException {
        BufferedReader input = new BufferedReader(new FileReader("KDC_Log.txt"));
        String last ="", line ="";

        while ((line = input.readLine()) != null) {
            last = line;
        }
        return last;
    }
    public static byte[] ReadFile(String FilePath) throws IOException {
        File f = new File(FilePath);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();
        return keyBytes;
    }

    public static byte[] Create_Digital_Signature( String Path, PrivateKey Key) throws Exception {
        byte[] input = ReadFile(Path);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(Key);
        signature.update(input);
        return signature.sign();
    }

    public static boolean Verify_Digital_Signature(String Path, byte[] signatureToVerify, PublicKey key) throws Exception {
        byte[] input = ReadFile(Path);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(input);
        return signature.verify(signatureToVerify);
    }

}