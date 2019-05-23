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
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Logger;

public class Client {

    private Socket socket;
    private String command;
    private HostPort serverHost;
    private String peer;
    private String identity;
    private SecretKey secretKey;
    private PrivateKey privateKey;
    private static final Logger log = Logger.getLogger(Client.class.getName());

    public Client(String command, String server, String peer, String identity) throws Exception {
        socket = null;
        this.command = command;
        this.serverHost = new HostPort(server);
        this.peer = peer;
        this.identity = identity;
        privateKey = BitboxKey.getPrivateKey("keyfiles/private_key.der");
    }

    public void start() throws IOException {
        try {
            socket = new Socket(serverHost.host, serverHost.port);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            BufferedWriter output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
            sendAuthorizationRequest(output);
            if (command == "list_peers"){
                log.info("[Client] Sending LIST_PEER_REQUEST to:" + serverHost.toString());
                Document listPeerRequest = Protocol.createListPeerRequest();
                String result = BitboxKey.AES_Encryption(listPeerRequest.toJson(), secretKey);
                Document payload = Protocol.createPayload(result);
                output.write(payload.toJson());
                output.newLine();
                output.flush();
            }
            if (command == "connect_peer"){
                log.info("[Client] Sending CONNECT_PEER_REQUEST to:" + serverHost.toString());
                Document connectPeerRequest = Protocol.createConnectPeerRequest(serverHost);
                String result = BitboxKey.AES_Encryption(connectPeerRequest.toJson(), secretKey);
                Document payload = Protocol.createPayload(result);
                output.write(payload.toJson());
                output.newLine();
                output.flush();

            }
            if (command == "disconnect_peer"){
                log.info("[Client] Sending DISCONNECT_PEER_REQUEST to:" + serverHost.toString());
                Document disconnectPeerRequest = Protocol.createDisconnectPeerRequest(serverHost);
                String result = BitboxKey.AES_Encryption(disconnectPeerRequest.toJson(), secretKey);
                Document payload = Protocol.createPayload(result);
                output.write(payload.toJson());
                output.newLine();
                output.flush();
            }

            while (true) {
                String message;

                if (secretKey != null){
                    message = BitboxKey.AES_Decryption(input.readLine(), secretKey);
                }
                else
                {
                    message = input.readLine();
                }

                Document JSON = Document.parse(message);

                switch (JSON.getString("command")) {
                    case "AUTH_RESPONSE":{
                        log.info("[Client] A auth response was received from " + serverHost.toString());
                        if(JSON.getBoolean("status"))
                        {
                            String key = JSON.getString("AES128");
                            secretKey = BitboxKey.DecryptSecretKey(key, privateKey);
                            log.info("[Client] Authorization success" );
                        }
                        else
                        {
                            log.info(String.format("[Client] Authorization fail because %s" ,JSON.getString("message")));
                            return;
                        }
                    }
                    case "LIST_PEERS_RESPONSE": {
                        log.info("[Client] A list peers response was received from " + serverHost.toString());
                        for (Document peer : (ArrayList<Document>) JSON.get("peers")) {

                            log.info(String.format("[Client] The currently connected peer is %s: %s",
                                    peer.getString("host"),
                                    peer.getInteger("port")));
                        }
                        break;
                    }
                    case "CONNECT_PEER_RESPONSE": {
                        log.info("[Client] A connect peer response was received from " + serverHost.toString());
                        log.info(JSON.getString("message"));
                        break;
                    }
                    case "DISCONNECT_PEER_RESPONSE ": {
                        log.info("[Client] A disconnect peer response was received from " + serverHost.toString());
                        log.info(JSON.getString("message"));
                        break;
                    }

                }
            }
        } finally {
            if (socket != null)
                socket.close()                                                           ;
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
