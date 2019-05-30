package unimelb.bitbox;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import unimelb.bitbox.util.BitboxKey;
import unimelb.bitbox.util.CommandLineArgument;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.HostPort;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.logging.Logger;

public class Client {

    private Socket socket;
    private String command;
    public HostPort serverHost;
    private String peer;
    private String identity;
    private SecretKey secretKey;
    private PrivateKey privateKey;
    private static final Logger log = Logger.getLogger(Client.class.getName());

    public Client(String command, String server, String peer, String identity) throws Exception {
        this.command = command;
        this.serverHost = new HostPort(server);
        this.peer = peer;
        this.identity = identity;
        privateKey = BitboxKey.getPrivateKey("keyfiles/jajaja_privatekey");
    }

    public void start() throws IOException {
        try {
            boolean completed = false;
            socket = new Socket(serverHost.host, serverHost.port);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
            sendAuthorizationRequest(output);

            while (!completed) {
                String message;

                if (secretKey != null)
                    message = BitboxKey.AES_Decryption(Document.parse(input.readLine()).getString("payload"), secretKey);
                else
                    message = input.readLine();

                Document JSON = Document.parse(message);

                switch (JSON.getString("command")) {
                    case "AUTH_RESPONSE": {
                        log.info("[Client] A auth response was received from " + serverHost.toString());
                        if (JSON.getBoolean("status")) {
                            String key = JSON.getString("AES128");
                            secretKey = BitboxKey.DecryptSecretKey(key, privateKey);
                            log.info("[Client] Authorization success");
                            processCommands(output);

                        } else
                            log.info(String.format("[Client] Authorization fail because %s", JSON.getString("message")));

                        break;
                    }
                    case "LIST_PEERS_RESPONSE": {
                        log.info("[Client] A list peers response was received from " + serverHost.toString());
                        for (Document peer : (ArrayList<Document>) JSON.get("peers"))
                            System.out.println(String.format("%s:%s", peer.getString("host"), peer.getLong("port")));

                        completed = true;
                        break;
                    }
                    case "CONNECT_PEER_RESPONSE": {
                        log.info("[Client] A connect peer response was received from " + serverHost.toString());
                        log.info(JSON.getString("message"));

                        completed = true;
                        break;
                    }
                    case "DISCONNECT_PEER_RESPONSE": {
                        log.info("[Client] A disconnect peer response was received from " + serverHost.toString());
                        log.info(JSON.getString("message"));

                        completed = true;
                        break;
                    }

                }
            }

            input.close();
            output.close();
            socket.close();
        } catch (SocketException e) {
            e.printStackTrace();
        }

    }

    private void processCommands(BufferedWriter output) throws IOException {
        if (command.equals("list_peers")){
            log.info("[Client] Sending LIST_PEER_REQUEST to:" + serverHost.toString());
            Document listPeerRequest = Protocol.createListPeerRequest();
            String result = BitboxKey.AES_Encryption(listPeerRequest.toJson(), secretKey);
            Document payload = Protocol.createPayload(result);
            output.write(payload.toJson());
            output.newLine();
            output.flush();
        }
        else if (command.equals("connect_peer")){
            log.info("[Client] Sending CONNECT_PEER_REQUEST to:" + serverHost.toString());
            Document connectPeerRequest = Protocol.createConnectPeerRequest(new HostPort(peer));
            String result = BitboxKey.AES_Encryption(connectPeerRequest.toJson(), secretKey);
            Document payload = Protocol.createPayload(result);
            output.write(payload.toJson());
            output.newLine();
            output.flush();

        }
        else if (command.equals("disconnect_peer")){
            log.info("[Client] Sending DISCONNECT_PEER_REQUEST to:" + serverHost.toString());
            Document disconnectPeerRequest = Protocol.createDisconnectPeerRequest(new HostPort(peer));
            String result = BitboxKey.AES_Encryption(disconnectPeerRequest.toJson(), secretKey);
            Document payload = Protocol.createPayload(result);
            output.write(payload.toJson());
            output.newLine();
            output.flush();
        }
    }

    private void sendAuthorizationRequest(BufferedWriter out) throws IOException {
        Document authorizationRequest = Protocol.createAuthorizationRequest(identity);
        out.write(authorizationRequest.toJson());
        out.newLine();
        out.flush();
        log.info("[Client] Sent an AUTH_REQUEST to " + serverHost.toString());
        log.info(authorizationRequest.toJson());
    }

    public static void main(String[] args) throws Exception {

        CommandLineArgument commandLineArgument = new CommandLineArgument();
        //Parser provided by args4j
        CmdLineParser parser = new CmdLineParser(commandLineArgument);
        try {
            //Parse the arguments
            parser.parseArgument(args);

            //After parsing, the fields in argsBean have been updated with the given
            //command line arguments
            String command = commandLineArgument.getCommand();
            String server = commandLineArgument.getServer();
            String peer = commandLineArgument.getPeer();
            String identity = commandLineArgument.getIdentity();

            //ServerThread serverThread = new ServerThread();
            //serverThread.start();

            new Client(command, server, peer, identity).start();

        } catch (CmdLineException e) {

            System.err.println(e.getMessage());

            //Print the usage to help the user understand the arguments expected
            //by the program
            parser.printUsage(System.err);
        }
    }
}
