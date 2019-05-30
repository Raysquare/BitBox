package unimelb.bitbox;

import unimelb.bitbox.util.*;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Logger;

public abstract class Server implements FileSystemObserver {
    protected int maxConnections;
    protected final String[] initialPeers;
    protected final FileSystemManager fileSystemManager;
    protected final long blockSize;
    protected final String advertisedName;

    protected static final Logger log = Logger.getLogger(Peer.class.getName());

    public Server() throws NoSuchAlgorithmException, IOException
    {
        fileSystemManager = new FileSystemManager(Configuration.getConfigurationValue("path"), this);
        blockSize = Long.parseLong(Configuration.getConfigurationValue("blockSize").trim());

        String initialPeersValue = Configuration.getConfigurationValue("peers");
        initialPeers = initialPeersValue.equals("") ? null : initialPeersValue.split(",");
        maxConnections = Integer.parseInt(Configuration.getConfigurationValue("maximumIncommingConnections").trim());
        advertisedName = Configuration.getConfigurationValue("advertisedName").trim();
    }

    // Set a timer to run 'generateSyncEvents' repetitively based on the configuration file
    protected void setTimerForGenerateSyncEvents()
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
        Connect to the peers in the configuration file, send handshake request,
        and add them into 'connectedPeers'
     */
    protected void connectInitialPeers()
    {
        if (initialPeers == null)
            return;

        for (String peer : initialPeers) {
            addNewPeer(peer);
            synchronized (this) {++maxConnections;}
        }
    }

    protected Document fileSystemEventHandler(FileSystemEvent fileSystemEvent, HostPort clientHostPort)
    {
        Document message = null;

        switch (fileSystemEvent.event) {
            case FILE_CREATE:
                message = Protocol.createFileCreateRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName);

                log.info("[LocalPeer] A file create event was received");
                log.info("[LocalPeer] Sent FILE_CREATE_REQUEST to " + clientHostPort.toString());
                log.info(message.toJson());
                break;

            case FILE_DELETE:
                message = Protocol.createFileDeleteRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName);

                log.info("[LocalPeer] A file delete event was received");
                log.info("[LocalPeer] Sent FILE_DELETE_REQUEST to " + clientHostPort.toString());
                log.info(message.toJson());
                break;

            case FILE_MODIFY:
                message = Protocol.createFileModifyRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName);

                log.info("[LocalPeer] A file modify event was received");
                log.info("[LocalPeer] Sent FILE_MODIFY_REQUEST to " + clientHostPort.toString());
                log.info(message.toJson());
                break;

            case DIRECTORY_CREATE:
                message = Protocol.createDirectoryCreateRequest(fileSystemEvent.pathName);

                log.info("[LocalPeer] A directory create event was received");
                log.info("[LocalPeer] Sent DIRECTORY_CREATE_REQUEST to " + clientHostPort.toString());
                log.info(message.toJson());
                break;

            case DIRECTORY_DELETE:
                message = Protocol.createDirectoryDeleteRequest(fileSystemEvent.pathName);

                log.info("[LocalPeer] A directory delete event was received");
                log.info("[LocalPeer] Sent DIRECTORY_DELETE_REQUEST to " + clientHostPort.toString());
                log.info(message.toJson());
                break;
        }

        return message;
    }

    public abstract void start() throws IOException;
    public abstract void addNewPeer(String peer);
    public abstract void removeFromConnectedPeers(String peer);
    public abstract ArrayList<Document> getConnectedPeerHostPort();
    public abstract boolean hasConnectedTo(String host, int port);
    public abstract boolean hasDisconnectedFrom(String host, int port);
    public abstract void processFileSystemEvent(FileSystemEvent fileSystemEvent);
}
