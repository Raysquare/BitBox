package unimelb.bitbox;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import unimelb.bitbox.util.CommandLineArgument;
import unimelb.bitbox.util.Configuration;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.HostPort;

import java.io.*;
import java.net.Socket;
import java.util.ArrayList;
import java.util.logging.Logger;

public class Client {

    private HostPort localHost;
    private Socket socket;
    private static final Logger log = Logger.getLogger(Client.class.getName());

    public Client() throws IOException {
        socket = null;


    }

    public void start() throws IOException {
        try {
            socket = new Socket(localHost.host, localHost.port);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
            String identity = "";
            Document authorizationRequest = Protocol.createAuthorizationRequest(identity);
            out.write(authorizationRequest.toJson());
            out.newLine();
            out.flush();
            log.info("[Client] Sent a authorization request to " + localHost.toString());
            log.info(authorizationRequest.toJson());
            while (true) {
                Document JSON = Document.parse(in.readLine());
                //TODO: Decryption
                switch (JSON.getString("command")) {
                    case "AUTH_RESPONSE":{
                        log.info("[Client] A auth response was received from " + localHost.toString());
                        if(JSON.getBoolean("status"))
                        {
                            //TODO: Decrypt the message and get the shared key
                            JSON.getString("AES128");
                            log.info("[Client] Authorization success" );
                        }else
                        {
                            log.info(String.format("[Client] Authorization fail because %s" ,JSON.getString("message")));
                            return;
                        }
                    }
                    case "LIST_PEERS_RESPONSE": {
                        log.info("[Client] A list peers response was received from " + localHost.toString());
                        for (Document peer : (ArrayList<Document>) JSON.get("peers")) {

                            log.info(String.format("[Client] The currently connected peer is %s: %s",
                                    peer.getString("host"),
                                    peer.getInteger("port")));
                        }
                        break;
                    }
                    case "CONNECT_PEER_RESPONSE": {
                        log.info("[Client] A connect peer response was received from " + localHost.toString());
                        log.info(JSON.getString("message"));
                        break;
                    }
                    case "DISCONNECT_PEER_RESPONSE ": {
                        log.info("[Client] A disconnect peer response was received from " + localHost.toString());
                        log.info(JSON.getString("message"));
                        break;
                    }

                }
            }
        } finally {
            if (socket != null)
                socket.close();
        }

    }

    public static void main(String[] args) throws IOException {

        CommandLineArgument commandLineArgument = new CommandLineArgument();

        //Parser provided by args4j
        CmdLineParser parser = new CmdLineParser(commandLineArgument);
        try {

            //Parse the arguments
            parser.parseArgument(args);

            //After parsing, the fields in argsBean have been updated with the given
            //command line arguments
            System.out.println("Command: " + commandLineArgument.getCommand());
            System.out.println("Server: " + commandLineArgument.getServer());
            System.out.println("Peer: " + commandLineArgument.getPeer());

        } catch (CmdLineException e) {

            System.err.println(e.getMessage());

            //Print the usage to help the user understand the arguments expected
            //by the program
            parser.printUsage(System.err);
        }

        new Client().start();
    }

}
