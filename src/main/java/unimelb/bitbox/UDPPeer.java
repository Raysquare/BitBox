package unimelb.bitbox;

import unimelb.bitbox.util.*;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

import javax.net.ServerSocketFactory;
import java.io.IOException;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class UDPPeer implements FileSystemObserver
{
    public long blockSize;
    public int udpTimeout;
    public int udpRetries;
    private int maxConnections;
    private String[] initialPeers;

    private HostPort localHost;
    private final ConcurrentHashMap<HostPort, UDPServerThread> connectedPeers;
    public FileSystemManager fileSystemManager;

    private static final Logger log = Logger.getLogger(Peer.class.getName());

    public UDPPeer() throws IOException, NoSuchAlgorithmException
    {
        fileSystemManager = new FileSystemManager(Configuration.getConfigurationValue("path"), this);
        blockSize = Long.parseLong(Configuration.getConfigurationValue("blockSize").trim());
        udpTimeout = Integer.parseInt(Configuration.getConfigurationValue("udpTimeout"));
        udpRetries = Integer.parseInt(Configuration.getConfigurationValue("udpRetries"));

        String initialPeersValue = Configuration.getConfigurationValue("peers");
        initialPeers = initialPeersValue.equals("") ? null : initialPeersValue.split(",");
        maxConnections = Integer.parseInt(Configuration.getConfigurationValue("maximumIncommingConnections").trim());
        connectedPeers = new ConcurrentHashMap<HostPort, UDPServerThread>(maxConnections);

        /*
        // get public ip
        URL url = new URL("http://bot.whatismyipaddress.com");
        BufferedReader responds = new BufferedReader(new InputStreamReader(url.openStream()));
        String hostAddress = responds.readLine().trim();
        */

        String hostAddress = Configuration.getConfigurationValue("advertisedName").trim();
        localHost = new HostPort(hostAddress, Integer.parseInt(Configuration.getConfigurationValue("udpPort").trim()));
    }

    /*
        Connect to the peers in the configuration file, send handshake request,
        and add them into 'connectedPeers'
     */
    private void connectInitialPeers(DatagramSocket socket) throws UnknownHostException
    {
        if (initialPeers == null)
            return;

        for (String peer : initialPeers) {
            HostPort clientHost = new HostPort(peer.trim());
            clientHost.host = InetAddress.getByName(clientHost.host).getHostAddress();

            try {
                log.info("[LocalPeer] Connected to " + peer);

                UDPServerThread serverThread = new UDPServerThread(this, socket, localHost, clientHost);
                serverThread.sendHandshakeRequest();
                serverThread.start(); // start the thread
                connectedPeers.put(clientHost, serverThread);
                synchronized (this) {++maxConnections;}

            } catch (IOException e) {
                log.info("[LocalPeer] Failed to connect to " + peer);
                e.printStackTrace();
            }
        }
    }

    /*
        Set a timer to run 'generateSyncEvents' repetitively based on the configuration file
     */
    private void setTimerForGenerateSyncEvents()
    {
        int syncInterval = Integer.parseInt(Configuration.getConfigurationValue("syncInterval").trim()) * 1000;

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
        DatagramSocket socket = new DatagramSocket(localHost.port);
        connectInitialPeers(socket);
        setTimerForGenerateSyncEvents();

        while (true) {
            byte[] buffer = new byte[65536];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

            socket.receive(packet);
            // create a new thread and put it into 'connectedPeer' after getting a connection
            String clientAddress = packet.getAddress().getHostAddress();
            int clientPort = packet.getPort();
            HostPort clientHost = new HostPort(clientAddress, clientPort);

            UDPServerThread serverThread = connectedPeers.get(clientHost);
            if (serverThread == null) {
                serverThread = new UDPServerThread(this, socket, localHost, new HostPort(clientAddress, clientPort));
                serverThread.start();
                connectedPeers.put(clientHost, serverThread);
            }

            serverThread.packetQueue.offer(packet);
        }
    }

    public boolean hasReachedMaxConnections()
    {
        synchronized (this) {
            return connectedPeers.size() > maxConnections;
        }
    }

    /*
        This method will be called by 'ServerThread' objects if there is a catastrophic error
        occurred in ServerThread
     */
    public void removeFromConnectedPeers(HostPort obj)
    {
        connectedPeers.remove(obj);
    }

    public void addNewPeer(HostPort hostport, UDPServerThread serverThread)
    {
        connectedPeers.put(hostport, serverThread);
    }

    /*
        This method will be called if the maximum connections has been reached. It returns the host and port of
        all the connected peers except the hostPort in the parameter
     */
    public ArrayList<Document> getConnectedPeerHostPort(HostPort hostPort)
    {
        ArrayList<Document> hostPorts = new ArrayList<Document>(connectedPeers.size());

        for (UDPServerThread peer : connectedPeers.values()) {
            if (!peer.clientSideServerHostPort.equals(hostPort))
                hostPorts.add(peer.clientSideServerHostPort.toDoc());
        }

        return hostPorts;
    }

    /*
        This method broadcasts file system event to each thread.

        In the program, there is one and only one instance of FileSystemManager to prevent the program from being
        trapped in race conditions, if not, each FileSystemManager instance
        in each thread will be monitoring the same folder, which causes system inconsistency.
     */
    public void processFileSystemEvent(FileSystemEvent fileSystemEvent)
    {
        for (UDPServerThread peer : connectedPeers.values())
            peer.processFileSystemEvent(fileSystemEvent);
    }

    public static void main(String[] args ) throws IOException, NumberFormatException, NoSuchAlgorithmException
    {
        System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tc] %2$s %4$s: %5$s%n");
        log.info("BitBox Peer starting...");

        new UDPPeer().start();
    }
}