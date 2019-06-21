package unimelb.bitbox;

import unimelb.bitbox.util.Configuration;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;
import unimelb.bitbox.util.HostPort;

import javax.net.ServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class TCPServer extends Server
{
    private final HostPort localHost;
    private final ArrayList<TCPServerThread> connectedPeers;

    public TCPServer() throws NoSuchAlgorithmException, IOException
    {
        super();
        connectedPeers = new ArrayList<>(maxConnections);
        localHost = new HostPort(advertisedName, Integer.parseInt(Configuration.getConfigurationValue("port").trim()));
    }

    // The main loop of the TCP server
    public void start() throws IOException
    {
        connectInitialPeers();
        setTimerForGenerateSyncEvents();
        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        ServerSocket server = factory.createServerSocket(localHost.port);

        while (true) {
            Socket socket = server.accept();

            String clientAddress = socket.getInetAddress().getHostAddress();
            int clientPort = socket.getPort();
            TCPServerThread serverThread = new TCPServerThread(this, socket, localHost, new HostPort(clientAddress, clientPort));
            serverThread.start();

            synchronized (connectedPeers) {
                connectedPeers.add(serverThread);
            }
        }
    }

    public void addNewPeer(String peer)
    {
        try {
            HostPort peerHost = new HostPort(peer.trim());

            Socket socket = new Socket(peerHost.host, peerHost.port);
            String clientAddress = socket.getInetAddress().getHostAddress();
            int clientPort = socket.getPort();

            TCPServerThread serverThread = new TCPServerThread(this, socket, localHost, new HostPort(clientAddress, clientPort));
            serverThread.sendHandshakeRequest();
            serverThread.start();

            log.info("[LocalPeer] Connected to " + peer);

            synchronized (connectedPeers) {connectedPeers.add(serverThread);}

        } catch (IOException e) {
            log.info("[LocalPeer] Failed to connect to " + peer);
        }
    }

    public boolean hasReachedMaxConnections()
    {
        synchronized (connectedPeers) {
            return connectedPeers.size() > maxConnections;
        }
    }

    /*
        This method will be called by 'TCPServerThread' objects if there is a catastrophic error
        occurred in ServerThread
     */
    public void removeFromConnectedPeers(TCPServerThread peer)
    {
        synchronized (connectedPeers) {
            connectedPeers.remove(peer);
        }
    }

    public void removeFromConnectedPeers(String peer)
    {
        HostPort peerHost = new HostPort(peer);
        try {
            peerHost.host = InetAddress.getByName(peerHost.host).getHostAddress();
        } catch (UnknownHostException e) {
            log.info("[LocalPeer] Unknown host: " + peer);
        }

        synchronized (connectedPeers) {
            for (TCPServerThread serverThread : connectedPeers) {
                if(peerHost.equals(serverThread.clientSideServerHostPort)) {
                    serverThread.close();
                }
            }
        }
    }

    public boolean hasConnectedTo(String host, int port) {
        HostPort peerHost = new HostPort(host, port);
        try {
            peerHost.host = InetAddress.getByName(peerHost.host).getHostAddress();
        } catch (UnknownHostException e) {
            log.info("[LocalPeer] Unknown host: " + peerHost.toString());
        }

        synchronized (connectedPeers) {
            for (TCPServerThread serverThread : connectedPeers) {
                if(peerHost.equals(serverThread.clientSideServerHostPort))
                    return serverThread.handshakeCompleted;
            }
        }

        return false;
    }

    public boolean hasDisconnectedFrom(String host, int port) {
        HostPort peerHost = new HostPort(host, port);
        try {
            peerHost.host = InetAddress.getByName(peerHost.host).getHostAddress();
        } catch (UnknownHostException e) {
            log.info("[LocalPeer] Unknown host: " + peerHost.toString());
        }

        synchronized (connectedPeers) {
            for (TCPServerThread serverThread : connectedPeers) {
                if(peerHost.equals(serverThread.clientSideServerHostPort))
                    return false;
            }
        }

        return true;
    }

    /*
            This method will be called if the maximum connections has been reached. It returns the host and port of
            all the connected peers except the hostPort in the parameter
         */
    public ArrayList<Document> getConnectedPeerHostPort(HostPort hostPort)
    {
        synchronized (connectedPeers) {
            ArrayList<Document> hostPorts = new ArrayList<Document>(connectedPeers.size());

            for (TCPServerThread peer : connectedPeers) {
                if (peer.clientSideServerHostPort != null && !hostPort.equals(peer.clientSideServerHostPort))
                    hostPorts.add(peer.clientSideServerHostPort.toDoc());
            }

            return hostPorts;
        }
    }

    public ArrayList<Document> getConnectedPeerHostPort()
    {
        return getConnectedPeerHostPort(null);
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
            for (TCPServerThread peer : connectedPeers)
                peer.processFileSystemEvent(fileSystemEvent);
        }
    }
}