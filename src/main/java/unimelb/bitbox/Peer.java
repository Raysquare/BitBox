package unimelb.bitbox;

import unimelb.bitbox.util.*;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

import javax.net.ServerSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Logger;

public class Peer implements FileSystemObserver
{
    private int maxConnections;
    private String[] initialPeers;

    private HostPort localHost;
    private final ArrayList<ServerThread> connectedPeers;
    public FileSystemManager fileSystemManager;
    public long blockSize;

    private static final Logger log = Logger.getLogger(Peer.class.getName());

    public Peer() throws IOException, NoSuchAlgorithmException
    {
        fileSystemManager = new FileSystemManager(Configuration.getConfigurationValue("path"), this);
        blockSize = Long.parseLong(Configuration.getConfigurationValue("blockSize"));

        String initialPeersValue = Configuration.getConfigurationValue("peers");
        initialPeers = initialPeersValue.equals("") ? null : initialPeersValue.split(",");
        maxConnections = Integer.parseInt(Configuration.getConfigurationValue("maximumIncommingConnections"));
        connectedPeers = new ArrayList<ServerThread>(maxConnections);

        // get public ip
        URL url = new URL("http://bot.whatismyipaddress.com");
        BufferedReader responds = new BufferedReader(new InputStreamReader(url.openStream()));

        String hostAddress = responds.readLine().trim();
        localHost = new HostPort(hostAddress, Integer.parseInt(Configuration.getConfigurationValue("port")));
    }

    /*
        Connect to the peers in the configuration file, send handshake request,
        and add them into 'connectedPeers'
     */
    private void connectInitialPeers()
    {
        if (initialPeers == null)
            return;

        for (String peer : initialPeers) {
            String[] address = peer.trim().split(":");
            String ip = address[0];
            int port = Integer.parseInt(address[1]);

            try {
                Socket socket = new Socket(ip, port);
                String clientAddress = socket.getInetAddress().getHostAddress();
                int clientPort = socket.getPort();
                log.info("[LocalPeer] Connected to " + peer);

                ServerThread serverThread = new ServerThread(this, socket, localHost, new HostPort(clientAddress, clientPort));
                serverThread.sendHandshakeRequest();
                serverThread.start(); // start the thread
                connectedPeers.add(serverThread);
                synchronized (connectedPeers) {++maxConnections;}

            } catch (IOException e) {
                log.info("[LocalPeer] Failed to connect to " + peer);
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
                log.info("[LocalPeer] Synchronization events were generated");
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
        connectInitialPeers();
        setTimerForGenerateSyncEvents();
        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        ServerSocket server = factory.createServerSocket(localHost.port);

        while (true) {
            Socket socket = server.accept();

            // create a new thread and put it into 'connectedPeer' after getting a connection
            String clientAddress = socket.getInetAddress().getHostAddress();
            int clientPort = socket.getPort();
            ServerThread serverThread = new ServerThread(this, socket, localHost, new HostPort(clientAddress, clientPort));
            serverThread.start();
            synchronized (connectedPeers) {
                connectedPeers.add(serverThread);
            }
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
    public void removeFromConnectedPeers(ServerThread obj)
    {
        synchronized (connectedPeers) {
            connectedPeers.remove(obj);
        }
    }

    /*
        This method will be called if the maximum connections has been reached. It returns the host and port of
        all the connected peers except the hostPort in the parameter
     */
    public ArrayList<Document> getConnectedPeerHostPort(HostPort hostPort)
    {
        synchronized (connectedPeers) {
            ArrayList<Document> hostPorts = new ArrayList<Document>(connectedPeers.size());

            for (ServerThread peer : connectedPeers) {
                if (!peer.clientHostPort.equals(hostPort))
                    hostPorts.add(peer.clientHostPort.toDoc());
            }

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
            for (ServerThread peer : connectedPeers)
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