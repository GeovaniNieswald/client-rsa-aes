package client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Client {

    private final SecretKey CHAVE_AES;
    private PublicKey publicKey;

    public Client() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        CHAVE_AES = generator.generateKey();
    }

    public static void main(String[] args) {
        try {
            Client cliente = new Client();

            System.out.println("---------------------------------------------------------");
            System.out.println("Estabelecendo Conexao...");
            Socket socket = new Socket("localhost", 5555);
            System.out.println("Conexao Estabelecida");
            System.out.println("---------------------------------------------------------\n");

            cliente.tratarConexao(socket);

            socket.close();

            System.out.println("\nConexao Finalizada");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String byteArrayToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public void tratarConexao(Socket socket) throws IOException, ClassNotFoundException {
        ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

        // ----------------- PEDE CHAVE PUBLICA -----------------
        String msg = "Preciso da Chave Publica";
        output.writeUTF(msg);
        output.flush();

        System.out.println("Saida: " + msg);
        System.out.println("");
        // -------------------------------------------------------

        // ----------------- RECEBE CHAVE PUBLICA ----------------
        this.publicKey = (PublicKey) input.readObject();
        String strPublicKey = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());

        System.out.println("Entrada: Chave Publica Recebida");
        System.out.println("Chave Publica Crua: " + strPublicKey);
        System.out.println("");
        // -------------------------------------------------------

        // ----------------- ENVIA CHAVE AES ---------------------
        String strChaveAES = Base64.getEncoder().encodeToString(this.CHAVE_AES.getEncoded());
        byte[] chaveAEScripRSA = CriptografiaRSA.criptografar(strChaveAES, this.publicKey);
        String strChaveAEScripRSA = this.byteArrayToBase64(chaveAEScripRSA);
        output.writeUTF(strChaveAEScripRSA);
        output.flush();

        System.out.println("Saida: Chave AES Criptografada Enviada");
        System.out.println("Chave AES Crua: " + strChaveAES);
        System.out.println("Chave AES Criptografada com RSA: " + strChaveAEScripRSA);
        System.out.println("");
        // -------------------------------------------------------

        // ----------------- ENVIA LOGIN E SENHA -----------------
        String login = "teste@teste.teste.com";
        byte[] loginCriptografado = CriptografiaAES.criptografar(login, this.CHAVE_AES);
        String strLoginCripAES = this.byteArrayToBase64(loginCriptografado);
        output.writeUTF(strLoginCripAES);
        output.flush();

        String senha = "f87asf7eSDS";
        byte[] senhaCriptografada = CriptografiaAES.criptografar(senha, this.CHAVE_AES);
        String strSenhaCripAES = this.byteArrayToBase64(senhaCriptografada);
        output.writeUTF(strSenhaCripAES);
        output.flush();

        System.out.println("Saida: Login e Senha Enviados");
        System.out.println("Login Cru: " + login);
        System.out.println("Login Criptografado com AES: " + strLoginCripAES);
        System.out.println("Senha Crua: " + senha);
        System.out.println("Senha Criptografada com AES: " + strSenhaCripAES);
        // -------------------------------------------------------

        output.close();
        input.close();
    }

}
