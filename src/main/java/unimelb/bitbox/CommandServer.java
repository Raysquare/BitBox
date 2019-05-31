package unimelb.bitbox;

import unimelb.bitbox.util.BitboxKey;
import unimelb.bitbox.util.Configuration;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.HostPort;

import javax.crypto.SecretKey;
import javax.net.ServerSocketFactory;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.logging.Logger;

import static java.lang.Thread.sleep;

public class CommandServer{

    private Socket clientSocket;
    private BufferedReader input;
    private BufferedWriter output;
    private Server server;
    private int localport;
    private SecretKey secretKey;

    private HashMap<String, String> keyIdentityList = new HashMap<String, String>();
    private static final Logger log = Logger.getLogger(CommandServer.class.getName());

    public CommandServer(Server peerServer)
    {
        server = peerServer;
        localport = Integer.parseInt(Configuration.getConfigurationValue("clientPort"));
        String keys = Configuration.getConfigurationValue("authorized_keys");
        String[] splitKey = keys.split(",");
        createIdentities(splitKey);
    }

    public void createIdentities(String[] splitKey){
        for (int index = 0; index < splitKey.length; index ++){
            String[] keyIdentity = splitKey[index].trim().split(" ");
            String key = splitKey[index];
            String identity = keyIdentity[2];
            keyIdentityList.put(identity, key);
        }
    }

    public void start() throws IOException {
        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        ServerSocket serverSocket = null;
        try {
            serverSocket = factory.createServerSocket(localport);
        } catch (IOException e) {
            log.info("[CommandServer] Unable to bind to the port");
            return;
            //e.printStackTrace();
        }


        while (true) {
            clientSocket = serverSocket.accept();
            boolean completed = false;
            secretKey = null;

            try {
                String clientAddress = clientSocket.getInetAddress().getHostAddress();
                int clientPort = clientSocket.getPort();
                HostPort clientHost = new HostPort(clientAddress, clientPort);
                input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
                output = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8));

                while (!completed) {
                    String message;

                    if (secretKey != null)
                        message = BitboxKey.AES_Decryption(Document.parse(input.readLine()).getString("payload"), secretKey);
                    else
                        message = input.readLine();

                    Document JSON = Document.parse(message);

                    switch (JSON.getString("command")) {
                        case "AUTH_REQUEST": {
                            log.info("[CommandSever] A auth request was received from " + clientHost.toString());

                            if (keyIdentityList.containsKey(JSON.getString("identity"))) {
                                String identity = JSON.getString("identity");
                                String publicKey = keyIdentityList.get(identity);
                                secretKey = BitboxKey.generateSecretKey();
                                String key = BitboxKey.EncryptSecretKey(BitboxKey.StringToPublicKey(publicKey), secretKey);
                                Document authResponse = Protocol.createAuthorizationResponse(key, true, "public key is found");
                                output.write(authResponse.toJson());
                                output.newLine();
                                output.flush();

                            } else {
                                Document authResponse = Protocol.createAuthorizationResponse(false, "public key isn't found");
                                output.write(authResponse.toJson());
                                output.newLine();
                                output.flush();
                                log.info("[CommandServer] public key isn't found");
                                completed = true;
                            }
                            break;
                        }
                        case "LIST_PEERS_REQUEST": {
                            log.info("[CommandServer] A LIST_PEERS_REQUEST was received from " + clientHost.toString());
                            Document listPeerResponse = Protocol.createListPeerResponse(server.getConnectedPeerHostPort());
                            String result = BitboxKey.AES_Encryption(listPeerResponse.toJson(), secretKey);
                            Document payload = Protocol.createPayload(result);
                            output.write(payload.toJson());
                            output.newLine();
                            output.flush();
                            completed = true;
                            break;
                        }
                        case "CONNECT_PEER_REQUEST": {
                            log.info("[CommandServer] A CONNECT_PEER_REQUEST was received from " + clientHost.toString());
                            Document hostPort = (Document) JSON.get("hostPort");
                            String host = hostPort.getString("host");
                            int port = (int) hostPort.getLong("port");
                            HostPort hostPortResponse = new HostPort(host, port);
                            Document connectPeerResponse;
                            server.addNewPeer(hostPortResponse.toString());
                            sleep(5000);
                            if (server.hasConnectedTo(host, port))
                                connectPeerResponse = Protocol.createConnectPeerResponse(hostPortResponse, true, "Successfully connected to " + hostPortResponse.toString());
                            else
                                connectPeerResponse = Protocol.createConnectPeerResponse(hostPortResponse, false, "Failed to connect to " + hostPortResponse.toString());

                            String result = BitboxKey.AES_Encryption(connectPeerResponse.toJson(), secretKey);
                            Document payload = Protocol.createPayload(result);
                            output.write(payload.toJson());
                            output.newLine();
                            output.flush();
                            completed = true;
                            break;
                        }
                        case "DISCONNECT_PEER_REQUEST": {
                            log.info("[CommandServer] A DISCONNECT_PEER_REQUEST was received from " + clientHost.toString());
                            Document hostPort = (Document) JSON.get("hostPort");
                            String host = hostPort.getString("host");
                            int port = (int) hostPort.getLong("port");
                            HostPort hostPortResponse = new HostPort(host, port);
                            Document disconnectPeerResponse;
                            server.removeFromConnectedPeers(hostPortResponse.toString());
                            sleep(5000);
                            if (server.hasDisconnectedFrom(host, port))
                                disconnectPeerResponse = Protocol.createDisconnectPeerResponse(hostPortResponse, true, "Successfully disconnected from " + hostPortResponse.toString());
                            else
                                disconnectPeerResponse = Protocol.createDisconnectPeerResponse(hostPortResponse, false, "Failed to disconnected from " + hostPortResponse.toString());

                            String result = BitboxKey.AES_Encryption(disconnectPeerResponse.toJson(), secretKey);
                            Document payload = Protocol.createPayload(result);
                            output.write(payload.toJson());
                            output.newLine();
                            output.flush();
                            completed = true;
                            break;
                        }
                    }
                }
            } catch (UnsupportedEncodingException | SocketException | InterruptedException e) {
                //e.printStackTrace();
            } catch (IOException e) {
                //e.printStackTrace();
            } catch (Exception e) {

            } finally {
                input.close();
                output.close();
                clientSocket.close();
            }
        }
    }
}