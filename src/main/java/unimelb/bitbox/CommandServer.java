package unimelb.bitbox;

import unimelb.bitbox.util.*;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Logger;

public class CommandServer extends Thread  {

    private Socket socket;
    private HostPort clientHostPort;
    private HostPort serverHostPort;
    private int clientPort;

    private ArrayList<String> connectedPeers;
    private static final Logger log = Logger.getLogger(Peer.class.getName());
    private HashMap<String, String> keyIdentityList = new HashMap<String, String>();
    private PublicKey publicKey;
    private BufferedReader input;
    private BufferedWriter output;
    private ConcurrentLinkedQueue<String> messageQueue;
    private CommandSenderThread senderThread;
    private String identity;

    public CommandServer(Client client, Socket socket, HostPort serverHostPort, HostPort clientHostPort) throws IOException, NoSuchAlgorithmException
    {
        connectedPeers = new ArrayList<>();
        clientPort = Integer.parseInt(Configuration.getConfigurationValue("clientPort").trim());
        clientHostPort = clientHostPort;
        serverHostPort = serverHostPort;
        String keys = Configuration.getConfigurationValue("authorized_keys");
        String[] splitKey = keys.split(",");
        createIdentities(splitKey);
        //publicKey = BitboxKey.StringToPublicKey();

        senderThread = new CommandSenderThread();
        senderThread.start();
    }

    public void createIdentities(String[] splitKey){
        for (int index = 0; index < splitKey.length; index ++){
            String[] keyIdentity = splitKey[index].split(" ");
            // I am not sure if the key is the whole text or just the 2 first texts until the identity
            String key = splitKey[index];
            String identity = keyIdentity[2];
            keyIdentityList.put(identity, key);
        }
    }

    class CommandSenderThread extends Thread {
        public void run() {
            try {
                while (!this.isInterrupted()) {
                    String message = messageQueue.poll();

                    if (message == null) {
                        this.sleep(500);
                        continue;
                    }

                    output.write(message);
                    output.newLine();
                    output.flush();
                }

            } catch (InterruptedException | SocketException e) {

            } catch (IOException e) {

            } finally {
                // if the thread is interrupted, then sends the rest of outgoing messages
                // to the corresponding peer
                try {
                    while (!messageQueue.isEmpty()) {
                        String message = messageQueue.poll();

                        if (message == null) {
                            continue;
                        }

                        output.write(message);
                        output.newLine();
                        output.flush();
                    }

                } catch (SocketException e) {
                } catch (IOException e) {}
            }
        }
    }

    /*
        This method process all the protocol commands.
     */
    public void run()
    {
        try {
            while (true) {
                Document JSON = Document.parse(input.readLine());
                //log.info(JSON.toJson());
                // TODO DECRYPTION
                if (!Protocol.isValid(JSON)) {
                    // I am not sure if INVALID PROTOCOL is applicable to project 2, I think it doesn't because it is not found in specs

                    Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: the message misses required fields");
                    messageQueue.offer(errorMsg.toJson());

                    log.info("[Server] A message missing required fields was received from " + clientHostPort.toString());
                    log.info("[Server] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
                    log.info(errorMsg.toJson());
                    break;
                }

                switch (JSON.getString("command")) {
                    case "AUTH_REQUEST": {
                        log.info("[Server] A AUTH_REQUEST was received from " + clientHostPort.toString());
                        Document authorizationRequest = Protocol.createAuthorizationRequest(identity);
                        messageQueue.offer(authorizationRequest.toJson());
                        break;
                    }
                    case "LIST_PEERS_REQUEST": {
                        log.info("[Server] A LIST_PEERS_REQUEST was received from " + clientHostPort.toString());
                        Document listPeersRequest = Protocol.createListPeerRequest();
                        messageQueue.offer(listPeersRequest.toJson());
                        break;
                    }
                    case "CONNECT_PEER_REQUEST": {

                        log.info("[Server] A CONNECT_PEER_REQUEST was received from " + clientHostPort.toString());
                        Document connectPeerRequest = Protocol.createConnectPeerRequest(serverHostPort);
                        messageQueue.offer(connectPeerRequest.toJson());
                        break;
                    }
                    case "DISCONNECT_PEER_REQUEST": {
                        log.info("[Server] A DISCONNECT_PEER_REQUEST was received from " + clientHostPort.toString());
                        Document disconnectPeerRequest = Protocol.createDisconnectPeerRequest(serverHostPort);
                        messageQueue.offer(disconnectPeerRequest.toJson());
                        break;
                    }
                }

            }
        } catch (SocketException | NullPointerException e) {
            log.info("[Server] Unable to communicate with " + clientHostPort.toString() + ", disconnected!");

        } catch (IOException e) {
            log.info("[Server] Unable to communicate with " + clientHostPort.toString() + ", disconnected!");
        } finally {

            try {
                senderThread.interrupt();
                senderThread.join();

            } catch (InterruptedException v) {}

            close();
        }
    }

    private void close()
    {
        try {
            input.close();
            output.close();
            socket.close();

        } catch (IOException e) {
            log.info("[Server] Unable to close the socket connecting to " + clientHostPort.toString());
        }
    }
}
