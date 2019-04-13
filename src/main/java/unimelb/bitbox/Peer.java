package unimelb.bitbox;

import unimelb.bitbox.util.*;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

import javax.net.ServerSocketFactory;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Logger;

public class Peer implements FileSystemObserver
{
    private int maxConnections;
    private String[] predefinedPeers;

    private HostPort localHost;
    private ArrayList<ServerMain> connectedPeers;
    public FileSystemManager fileSystemManager;

    private static Logger log = Logger.getLogger(Peer.class.getName());

    public Peer() throws IOException, NoSuchAlgorithmException
    {
        fileSystemManager = new FileSystemManager(Configuration.getConfigurationValue("path"), this);

        predefinedPeers = Configuration.getConfigurationValue("peers").split(",");
        maxConnections = Integer.parseInt(predefinedPeers.length + Configuration.getConfigurationValue("maximumIncommingConnections"));
        connectedPeers = new ArrayList<ServerMain>(maxConnections);

        InetAddress hostAddress = InetAddress.getLocalHost();
        localHost = new HostPort(hostAddress.getHostAddress(), Integer.parseInt(Configuration.getConfigurationValue("port")));
    }

    /*
        Connect to the peers in the configuration file, send handshake request,
        and add them into 'connectedPeers'
     */
    private void connectPredefinedPeers()
    {
        for (String peer : predefinedPeers) {
            String[] address = peer.split(":");
            String ip = address[0];
            int port = Integer.parseInt(address[1]);

            try {
                Socket socket = new Socket(ip, port);
                String clientAddress = socket.getInetAddress().getHostAddress();
                int clientPort = socket.getPort();

                Document handshakeRequest = Protocol.createHandshakeRequest(localHost);
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                output.writeUTF(handshakeRequest.toJson());
                output.close();

                connectedPeers.add(new ServerMain(this, socket, localHost, new HostPort(clientAddress, clientPort)));

            } catch (IOException e) {
                log.info("Failed to connect to " + peer);
            }
        }
    }

    /*
        Set a timer to run 'generateSyncEvents' repetitively based on the configuration file
     */
    private void setTimerForGenerateSyncEvents()
    {
        int syncInterval = Integer.parseInt(Configuration.getConfigurationValue("syncInterval")) * 1000;

        new Timer().scheduleAtFixedRate(new TimerTask() {
            public void run() {
                log.info("Sync events generated");
                for (FileSystemEvent event : fileSystemManager.generateSyncEvents())
                    processFileSystemEvent(event);
            }
        }, 0, syncInterval);
    }

    /*
        The main loop of the peer program
     */
    public void start() throws IOException
    {
        connectPredefinedPeers();
        setTimerForGenerateSyncEvents();
        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        ServerSocket server = factory.createServerSocket(localHost.port);

        while (true) {
            Socket socket = server.accept();

            // create a new thread and put it into 'connectedPeer' after getting a connection
            String clientAddress = socket.getInetAddress().getHostAddress();
            int clientPort = socket.getPort();
            connectedPeers.add(new ServerMain(this, socket, localHost, new HostPort(clientAddress, clientPort)));
        }
    }

    public boolean hasReachedMaxConnections()
    {
        synchronized (connectedPeers) {
            return connectedPeers.size() > maxConnections;
        }
    }

    /*
        This method will be called by 'ServerMain' objects if receiving an invalid protocol or a handshake
        request after handshake has been completed
     */
    public void removeFromConnectedPeers(ServerMain obj)
    {
        synchronized (connectedPeers) {
            connectedPeers.remove(obj);
        }
    }

    /*
        This method will be called if the maximum connections has been reached. It returns the host and port of
        all the connected peers
     */
    public ArrayList<Document> getConnectedPeerHostPort()
    {
        synchronized (connectedPeers) {
            ArrayList<Document> hostPorts = new ArrayList<Document>(connectedPeers.size());

            for (ServerMain peer : connectedPeers)
                hostPorts.add(peer.clientHostPort.toDoc());


            return hostPorts;
        }
    }

    /*
        This method broadcasts file system event to each thread.

        In the program, there is one and only one instance of FileSystemManager to prevent the program from being
        trapped in race conditions, if not, each FileSystemManager instance
        in each thread will be monitoring the same folder, which causes system inconsistency.
     */
    public void processFileSystemEvent(FileSystemEvent fileSystemEvent)
    {
        synchronized (connectedPeers) {
            for (ServerMain peer : connectedPeers)
                peer.processFileSystemEvent(fileSystemEvent);
        }
    }

    public static void main(String[] args ) throws IOException, NumberFormatException, NoSuchAlgorithmException
    {
        System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tc] %2$s %4$s: %5$s%n");
        log.info("BitBox Peer starting...");

        new Peer().start();
    }
}