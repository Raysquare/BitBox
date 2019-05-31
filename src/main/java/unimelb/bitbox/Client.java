package unimelb.bitbox;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import unimelb.bitbox.util.BitboxKey;
import unimelb.bitbox.util.CommandLineArgument;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.HostPort;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.logging.Logger;

public class Client {
    private Socket socket;
    private String command;
    private HostPort serverHost;
    private String peer;
    private String identity;
    private SecretKey secretKey;
    private PrivateKey privateKey;
    private BufferedReader input;
    private BufferedWriter output;
    private static final Logger log = Logger.getLogger(Client.class.getName());

    public Client(String command, String server, String peer, String identity) throws Exception {
        this.command = command;
        this.serverHost = new HostPort(server);
        this.peer = peer;
        this.identity = identity;
        privateKey = BitboxKey.getPrivateKey("keyfiles/jajaja_privatekey");
    }

    public void start() throws IOException
    {
        try {
            socket = new Socket(serverHost.host, serverHost.port);
            input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
            sendAuthorizationRequest();

            while (true) {
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
                            processCommands();
                            break;

                        } else
                            log.info(String.format("[Client] Authorization failed because %s", JSON.getString("message")));

                        return;
                    }
                    case "LIST_PEERS_RESPONSE": {
                        log.info("[Client] A list peers response was received from " + serverHost.toString());
                        System.out.println("Peer lists:");

                        for (Document peer : (ArrayList<Document>) JSON.get("peers"))
                            System.out.println(String.format("%s:%s", peer.getString("host"), peer.getLong("port")));

                        return;
                    }
                    case "CONNECT_PEER_RESPONSE": {
                        log.info("[Client] A connect peer response was received from " + serverHost.toString());
                        log.info(JSON.getString("message"));

                        return;
                    }
                    case "DISCONNECT_PEER_RESPONSE": {
                        log.info("[Client] A disconnect peer response was received from " + serverHost.toString());
                        log.info(JSON.getString("message"));

                        return;
                    }

                    default:
                        System.out.println("The command in the commandline is invalid");
                        System.out.println("The command options are: list_peers, connect_peer, disconnect_peer");
                        return;
                }
            }
        } catch (ConnectException e) {
            log.info("[Client] Unable to connect to " + serverHost.toString());
        } catch (NullPointerException | SocketException e) {
            //e.printStackTrace();
        } finally {
            input.close();
            output.close();
            socket.close();
        }
    }

    private void processCommands() throws IOException
    {
        if (command.equals("list_peers")){
            log.info("[Client] Sending LIST_PEER_REQUEST to:" + serverHost.toString());
            Document listPeerRequest = Protocol.createListPeerRequest();
            String result = BitboxKey.AES_Encryption(listPeerRequest.toJson(), secretKey);
            Document payload = Protocol.createPayload(result);
            output.write(payload.toJson());
            output.newLine();
            output.flush();

        } else if (command.equals("connect_peer")){
            log.info("[Client] Sending CONNECT_PEER_REQUEST to:" + serverHost.toString());
            Document connectPeerRequest = Protocol.createConnectPeerRequest(new HostPort(peer));
            String result = BitboxKey.AES_Encryption(connectPeerRequest.toJson(), secretKey);
            Document payload = Protocol.createPayload(result);
            output.write(payload.toJson());
            output.newLine();
            output.flush();
            System.out.println("Please wait 5 seconds......");

        } else if (command.equals("disconnect_peer")){
            log.info("[Client] Sending DISCONNECT_PEER_REQUEST to:" + serverHost.toString());
            Document disconnectPeerRequest = Protocol.createDisconnectPeerRequest(new HostPort(peer));
            String result = BitboxKey.AES_Encryption(disconnectPeerRequest.toJson(), secretKey);
            Document payload = Protocol.createPayload(result);
            output.write(payload.toJson());
            output.newLine();
            output.flush();
            System.out.println("Please wait 5 seconds......");
        }
    }

    private void sendAuthorizationRequest() throws IOException
    {
        Document authorizationRequest = Protocol.createAuthorizationRequest(identity);
        output.write(authorizationRequest.toJson());
        output.newLine();
        output.flush();
        log.info("[Client] Sent an AUTH_REQUEST to " + serverHost.toString());
        log.info(authorizationRequest.toJson());
    }

    public static void main(String[] args) throws Exception
    {

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

            new Client(command, server, peer, identity).start();

        } catch (CmdLineException e) {

            System.err.println(e.getMessage());

            //Print the usage to help the user understand the arguments expected
            //by the program
            parser.printUsage(System.err);
        }
    }
}
