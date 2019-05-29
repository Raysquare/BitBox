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

public class UDPServer extends Server
{
    public final int udpTimeout;
    public final int udpRetries;
    private final HostPort localHost;
    private final DatagramSocket socket;
    private final ConcurrentHashMap<HostPort, UDPServerThread> connectedPeers;

    public UDPServer() throws IOException, NoSuchAlgorithmException
    {
        super();
        udpTimeout = Integer.parseInt(Configuration.getConfigurationValue("udpTimeout"));
        udpRetries = Integer.parseInt(Configuration.getConfigurationValue("udpRetries"));
        connectedPeers = new ConcurrentHashMap<>(maxConnections);
        localHost = new HostPort(advertisedName, Integer.parseInt(Configuration.getConfigurationValue("udpPort").trim()));
        socket = new DatagramSocket(localHost.port);
    }

    // The main loop of the UDP server
    public void start() throws IOException
    {
        connectInitialPeers();
        setTimerForGenerateSyncEvents();

        while (true) {
            byte[] buffer = new byte[8192];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

            socket.receive(packet);

            String clientAddress = packet.getAddress().getHostAddress();
            int clientPort = packet.getPort();
            HostPort clientHost = new HostPort(clientAddress, clientPort);

            UDPServerThread serverThread = connectedPeers.get(clientHost);

            if (serverThread == null) {
                serverThread = new UDPServerThread(this, socket, localHost, clientHost);
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
    public void removeFromConnectedPeers(HostPort peer)
    {
        connectedPeers.remove(peer);
    }

    public void removeFromConnectedPeers(String peer)
    {
        try {
            HostPort peerHost = new HostPort(peer);
            peerHost.host = InetAddress.getByName(peerHost.host).getHostAddress();
            connectedPeers.get(peerHost).interrupt();

        } catch (UnknownHostException e) {
            log.info("[LocalPeer] unable to remove the peer from the connected peer list");
        }
    }

    public void addNewPeer(HostPort hostport, UDPServerThread serverThread)
    {
        connectedPeers.put(hostport, serverThread);
    }

    public void addNewPeer(String peer)
    {
        try {
            HostPort clientHost = new HostPort(peer.trim());
            clientHost.host = InetAddress.getByName(clientHost.host).getHostAddress();

            UDPServerThread serverThread = new UDPServerThread(this, socket, localHost, clientHost);
            serverThread.sendHandshakeRequest();
            serverThread.start();
            connectedPeers.put(clientHost, serverThread);

            log.info("[LocalPeer] Connected to " + peer);

        } catch (IOException e) {
            log.info("[LocalPeer] Failed to connect to " + peer);
        }
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

    public ArrayList<Document> getConnectedPeerHostPort()
    {
        return getConnectedPeerHostPort(null);
    }

    public boolean hasConnectedTo(String host,int port) {
        try {
            HostPort peerHost = new HostPort(host, port);
            peerHost.host = InetAddress.getByName(peerHost.host).getHostAddress();
            UDPServerThread serverThread = connectedPeers.get(peerHost);

            if (serverThread != null && serverThread.clientSideServerHostPort.equals(peerHost))
                return serverThread.handshakeCompleted;

            return false;

        } catch (UnknownHostException e) {
            log.info("[LocalPeer] Couldn't find the peer in the connected peer list");
            return false;
        }
    }

    public boolean hasDisconnectedFrom(String host, int port) {
        try {
            HostPort peerHost = new HostPort(host, port);
            peerHost.host = InetAddress.getByName(peerHost.host).getHostAddress();
            UDPServerThread serverThread = connectedPeers.get(peerHost);

            return serverThread == null;

        } catch (UnknownHostException e) {
            log.info("[LocalPeer] Couldn't find the peer in the connected peer list");
            return false;
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
        for (UDPServerThread peer : connectedPeers.values())
            peer.processFileSystemEvent(fileSystemEvent);
    }
}