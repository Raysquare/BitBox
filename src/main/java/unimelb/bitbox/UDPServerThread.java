package unimelb.bitbox;

import unimelb.bitbox.util.*;
import unimelb.bitbox.util.FileSystemManager.FileDescriptor;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Logger;

class RequestRecord {
    public long timeStamp;
    public int numRetried;

    public RequestRecord(long timeStamp, int numRetried) {
        this.timeStamp = timeStamp;
        this.numRetried = numRetried;
    }
}

/*
    Each connection will have a server thread associated with it.
 */
public class UDPServerThread extends Thread implements FileSystemObserver
{
    private static final Logger log = Logger.getLogger(ServerThread.class.getName());
    private UDPPeer localPeer; // the delegate object to the Peer instance
    private DatagramSocket socket;
    private HostPort serverHostPort;
    private HostPort clientHostPort; // the host port that is used by client to connect to the local peer
    public HostPort clientSideServerHostPort; // the server host port on the client side
    private Timer retryTimer;
    private long lastimeGotResponseFromClient;

    private boolean handshakeCompleted;
    private LinkedList<HostPort> peerCandidates; // it is used to store peer list when receiving CONNECTION_REFUSED
    public ConcurrentLinkedQueue<DatagramPacket> packetQueue;
    public ConcurrentHashMap<String, RequestRecord> requestRecords; // only stores retry records for requests sent by the local peer

    private void retryFunction()
    {
        requestRecords.forEach((request, retryRecord) -> {
            long currentTime = new Date().getTime();

            if ((currentTime - retryRecord.timeStamp > localPeer.udpTimeout) &&
                ((retryRecord.numRetried < localPeer.udpRetries) ||
                 (!packetQueue.isEmpty()))) {

                if (retryRecord.numRetried < localPeer.udpRetries)
                    retryRecord.numRetried++;
                else
                    retryRecord.numRetried = 0;

                retryRecord.timeStamp = currentTime;
                sendPacket(request);

            } else if (retryRecord.numRetried >= localPeer.udpRetries) {
                retryTimer.cancel();
                this.interrupt();
                log.info("[LocalPeer] Retry fail: " + request);
                return;
            }
        });
    }

    public UDPServerThread(UDPPeer localPeer, DatagramSocket socket, HostPort serverHostPort, HostPort clientHostPort) throws IOException
    {
        handshakeCompleted = false;
        this.socket = socket;
        this.localPeer = localPeer;
        this.serverHostPort = serverHostPort;
        this.clientHostPort = clientHostPort;

        peerCandidates = new LinkedList<HostPort>();
        packetQueue = new ConcurrentLinkedQueue<DatagramPacket>();
        requestRecords = new ConcurrentHashMap<String, RequestRecord>();

        retryTimer = new Timer();
        retryTimer.scheduleAtFixedRate(new TimerTask() {
            public void run() {retryFunction();}
        }, 0, 1000);
    }

    public void sendPacket(String message)
    {
        try {
            byte[] bytes = message.getBytes("UTF-8");
            DatagramPacket packet = new DatagramPacket(bytes, bytes.length, InetAddress.getByName(clientHostPort.host), clientHostPort.port);
            socket.send(packet);

        } catch (IOException e) {
            e.printStackTrace();
            this.interrupt();
        }
    }

    public void sendHandshakeRequest()
    {
        String handshakeRequest = Protocol.createHandshakeRequest(serverHostPort).toJson();

        sendPacket(handshakeRequest);
        requestRecords.put(handshakeRequest, new RequestRecord(new Date().getTime(), 0));

        log.info("[LocalPeer] Sent a handshake request to " + clientHostPort.toString());
        log.info(handshakeRequest);
    }

    public void sendFileBytesRequest(FileDescriptor fileDescriptor, String pathName, long position, long size)
    {
        long length = Math.min(localPeer.blockSize, size);
        String fileByteMessage = Protocol.createFileBytesRequest(fileDescriptor, pathName, position, length).toJson();

        sendPacket(fileByteMessage);
        requestRecords.put(fileByteMessage, new RequestRecord(new Date().getTime(), 0));

        log.info("[LocalPeer] Sent FILE_BYTES_REQUEST to " + clientHostPort.toString());
        log.info((fileByteMessage));
    }

    /*
        This methods creates corresponding messages when receiving file system events
     */
    public void processFileSystemEvent(FileSystemEvent fileSystemEvent)
    {
        if (!handshakeCompleted)
            return;

        switch (fileSystemEvent.event) {
            case FILE_CREATE:
                String message = Protocol.createFileCreateRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName).toJson();
                sendPacket(message);
                requestRecords.put(message, new RequestRecord(new Date().getTime(), 0));

                log.info("[LocalPeer] A file create event was received");
                log.info("[LocalPeer] Sent FILE_CREATE_REQUEST to " + clientHostPort.toString());
                log.info(message);
                break;

            case FILE_DELETE:
                message = Protocol.createFileDeleteRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName).toJson();
                sendPacket(message);
                requestRecords.put(message, new RequestRecord(new Date().getTime(), 0));

                log.info("[LocalPeer] A file delete event was received");
                log.info("[LocalPeer] Sent FILE_DELETE_REQUEST to " + clientHostPort.toString());
                log.info(message);
                break;

            case FILE_MODIFY:
                message = Protocol.createFileModifyRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName).toJson();
                sendPacket(message);
                requestRecords.put(message, new RequestRecord(new Date().getTime(), 0));

                log.info("[LocalPeer] A file modify event was received");
                log.info("[LocalPeer] Sent FILE_MODIFY_REQUEST to " + clientHostPort.toString());
                log.info(message);
                break;

            case DIRECTORY_CREATE:
                message = Protocol.createDirectoryCreateRequest(fileSystemEvent.pathName).toJson();
                sendPacket(message);
                requestRecords.put(message, new RequestRecord(new Date().getTime(), 0));

                log.info("[LocalPeer] A directory create event was received");
                log.info("[LocalPeer] Sent DIRECTORY_CREATE_REQUEST to " + clientHostPort.toString());
                log.info(message);
                break;

            case DIRECTORY_DELETE:
                message = Protocol.createDirectoryDeleteRequest(fileSystemEvent.pathName).toJson();
                sendPacket(message);
                requestRecords.put(message, new RequestRecord(new Date().getTime(), 0));

                log.info("[LocalPeer] A directory delete event was received");
                log.info("[LocalPeer] Sent DIRECTORY_DELETE_REQUEST to " + clientHostPort.toString());
                log.info(message);
                break;
        }
    }

    /*
        This method process all the protocol commands.
     */
    public void run()
    {
        FileSystemManager fileSystemManager = localPeer.fileSystemManager;

        try {
            while (!isInterrupted()) {
                DatagramPacket packet = packetQueue.poll();

                if (packet == null) {
                    sleep(10);
                    continue;
                }

                String data = new String(packet.getData(), 0, packet.getLength(), "UTF-8");
                Document JSON = Document.parse(data);
                //log.info(JSON.toJson());

                if (!Protocol.isValid(JSON)) {
                    String errorMsg = Protocol.createInvalidProtocol("Invalid protocol: the message misses required fields").toJson();
                    sendPacket(errorMsg);

                    log.info("[LocalPeer] A message missing required fields was received from " + clientHostPort.toString());
                    log.info("[LocalPeer] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
                    log.info(errorMsg);
                    break;
                }

                switch (JSON.getString("command")) {
                    case "HANDSHAKE_REQUEST": {
                        /*
                        if (handshakeCompleted) {
                            Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: handshake has been completed");
                            sendPacket(errorMsg);

                            log.info("[LocalPeer] Multiple handshakes were received from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());
                            return;
                        }
                        */
                        // store the host port sent from the peer
                        Document hostPort = (Document)JSON.get("hostPort");
                        clientSideServerHostPort = new HostPort(hostPort.getString("host").trim(), (int)hostPort.getLong("port"));

                        if (localPeer.hasReachedMaxConnections()) {
                            String errorString = "The maximum connections has been reached";
                            String errorMsg = Protocol.createConnectionRefused(errorString, localPeer.getConnectedPeerHostPort(clientSideServerHostPort)).toJson();
                            sendPacket(errorMsg);

                            log.info("[LocalPeer] The maximum connections were reached, disconnected from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent CONNECTION_REFUSED to " + clientHostPort.toString());
                            log.info(errorMsg);
                            return;
                        }

                        String message = Protocol.createHandshakeResponse(serverHostPort).toJson();
                        sendPacket(message);

                        handshakeCompleted = true;

                        log.info("[LocalPeer] A handshake request was received from " + clientHostPort.toString());
                        log.info("[LocalPeer] Sent HANDSHAKE_RESPONSE to " + clientHostPort.toString());
                        log.info((message));

                        for (FileSystemEvent event : fileSystemManager.generateSyncEvents())
                            processFileSystemEvent(event);

                        break;
                    }

                    case "HANDSHAKE_RESPONSE": {
                        String request = Protocol.createHandshakeRequest(serverHostPort).toJson();
                        if (!requestRecords.containsKey(request))
                            break;
                        requestRecords.remove(request);

                        log.info("[LocalPeer] A handshake response was received from " + clientHostPort.toString());

                        clientSideServerHostPort = clientHostPort;

                        handshakeCompleted = true;
                        peerCandidates.clear();

                        for (FileSystemEvent event : fileSystemManager.generateSyncEvents())
                            processFileSystemEvent(event);

                        break;
                    }

                    // try to connect to peers in the peer list in BFS order
                    case "CONNECTION_REFUSED": {
                        log.info("[LocalPeer] A connection refused message was received from " + clientHostPort.toString());
                        requestRecords.clear();

                        // get peers needed to try from the peer list
                        for (Document peer : (ArrayList<Document>)JSON.get("peers")) {
                            HostPort peerHostPort = new HostPort(peer.getString("host"), (int)peer.getLong("port"));

                            // remove duplicated peers
                            if (!peerCandidates.contains(peerHostPort))
                                peerCandidates.offer(peerHostPort);
                        }

                        // if there is no peer to connect, then closes the thread
                        if (peerCandidates.isEmpty())
                            return;

                        localPeer.removeFromConnectedPeers(clientHostPort);
                        // get a peer to connect
                        clientHostPort = peerCandidates.poll();

                        log.info("[LocalPeer] Trying to connect to " + clientHostPort.toString());

                        localPeer.addNewPeer(clientHostPort, this);
                        sendHandshakeRequest();

                        break;
                    }

                    case "FILE_CREATE_REQUEST": {
                        if (!handshakeCompleted)
                            break;

                        log.info("[LocalPeer] A file create request was received from " + clientHostPort.toString());

                        String pathName = JSON.getString("pathName");
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);

                        try {
                            if (!fileSystemManager.isSafePathName(pathName)) {
                                String errorString = "Path name is unsafe: File create request failed";
                                String errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false).toJson();

                                sendPacket(errorMsg);

                                log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                                log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                log.info(errorMsg);

                                // if the file with the same content exists, then reject the request
                            } else if (fileSystemManager.fileNameExists(pathName, fileDescriptor.md5)) {
                                String errorString = "File with the same content has existed: File create request failed";
                                String errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false).toJson();

                                sendPacket(errorMsg);

                                log.info("[LocalPeer] File with the same content has existed, refused request from " + clientHostPort.toString());
                                log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                log.info(errorMsg);

                                // if the file exists but with different content, then try to modify it
                            } else if (fileSystemManager.fileNameExists(pathName)) {

                                // if the file is newer, then reject the request, otherwise overwrite the current older file
                                if (!fileSystemManager.modifyFileLoader(pathName, fileDescriptor.md5, fileDescriptor.fileSize, fileDescriptor.lastModified)) {
                                    String errorString = "There is a newer version: File create request failed";
                                    String errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false).toJson();

                                    sendPacket(errorMsg);

                                    log.info("[LocalPeer] There is a newer version, refused request from " + clientHostPort.toString());
                                    log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                    log.info(errorMsg);

                                } else {
                                    String messageString = "Overwrite the older version";
                                    String message = Protocol.createFileCreateResponse(fileDescriptor, pathName, messageString, true).toJson();

                                    sendPacket(message);

                                    log.info("[LocalPeer] Overwrite the older version and get a new one from " + clientHostPort.toString());
                                    log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                    log.info(message);

                                    sendFileBytesRequest(fileDescriptor, pathName, 0, fileDescriptor.fileSize);
                                }

                            } else {
                                fileSystemManager.createFileLoader(pathName, fileDescriptor.md5, fileDescriptor.fileSize, fileDescriptor.lastModified);

                                // if there is a file with a different name but the same content, then reject the request, otherwise then the request is accepted
                                if (fileSystemManager.checkShortcut(pathName)) {
                                    String errorString = "There is a file with the same content, no need to transfer it again.";
                                    log.info("[LocalPeer] There is a file with the same content, no need to transfer it again from " + clientHostPort.toString());
                                    String errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false).toJson();

                                    sendPacket(errorMsg);
                                    break;
                                }

                                String messageString = "File loader ready";
                                String fileCreateMessage = Protocol.createFileCreateResponse(fileDescriptor, pathName, messageString, true).toJson();

                                sendPacket(fileCreateMessage);

                                log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                log.info(fileCreateMessage);

                                sendFileBytesRequest(fileDescriptor, pathName, 0, fileDescriptor.fileSize);

                            }

                        } catch (IOException e) {
                            String errorString = "Cannot create the file loader as it has already been created";
                            log.info("[LocalPeer] Cannot create the file loader, refused request from " + clientHostPort.toString());
                            String errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false).toJson();

                            sendPacket(errorMsg);
                        }

                        break;
                    }

                    case "FILE_CREATE_RESPONSE": {
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);
                        String request = Protocol.createFileCreateRequest(fileDescriptor, JSON.getString("pathName")).toJson();
                        if (!requestRecords.containsKey(request))
                            break;
                        requestRecords.remove(request);

                        log.info("[LocalPeer] A file create response was received from " + clientHostPort.toString());

                        if (!JSON.getBoolean("status"))
                            log.info(String.format("[LocalPeer] Couldn't create %s on %s because %s",
                                    JSON.getString("pathName"),
                                    clientHostPort.toString(),
                                    JSON.getString("message")));

                        break;
                    }

                    case "FILE_BYTES_REQUEST": {
                        if (!handshakeCompleted)
                            break;

                        log.info("[LocalPeer] A file bytes request was received from " + clientHostPort.toString());

                        String pathName = JSON.getString("pathName");
                        long position = JSON.getLong("position");
                        long length = Math.min(JSON.getLong("length"), localPeer.blockSize);
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);

                        byte[] bytes = fileSystemManager.readFile(fileDescriptor.md5, position, length).array();
                        String content = Base64.getEncoder().encodeToString(bytes);
                        String fileBytesMessage = Protocol.createFileBytesResponse(fileDescriptor, pathName, position, length, content, "successful read", true).toJson();

                        sendPacket(fileBytesMessage);

                        log.info("[LocalPeer] Sent FILE_BYTES_RESPONSE success to " + clientHostPort.toString());
                        log.info((fileBytesMessage));

                        break;
                    }

                    case"FILE_BYTES_RESPONSE": {
                        String pathName = JSON.getString("pathName");
                        long length = JSON.getLong("length");
                        long position = JSON.getLong("position");

                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);
                        String request = Protocol.createFileBytesRequest(fileDescriptor, pathName, position, length).toJson();
                        if (!requestRecords.containsKey(request))
                            break;
                        requestRecords.remove(request);

                        log.info("[LocalPeer] A file bytes response was received from " + clientHostPort.toString());

                        byte[] bytes = Base64.getDecoder().decode(JSON.getString("content"));
                        ByteBuffer content = ByteBuffer.wrap(bytes);

                        fileSystemManager.writeFile(pathName, content, JSON.getLong("position"));

                        position += length;
                        length = Math.min(fileDescriptor.fileSize - position, length);

                        if (!fileSystemManager.checkWriteComplete(pathName) && length != 0)
                            sendFileBytesRequest(fileDescriptor, pathName, position, length);

                        else
                            fileSystemManager.cancelFileLoader(pathName);

                        break;
                    }

                    case"FILE_DELETE_REQUEST": {
                        if (!handshakeCompleted)
                            break;

                        log.info("[LocalPeer] A file delete request was received from " + clientHostPort.toString());

                        String pathName = JSON.getString("pathName");
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);

                        if (!fileSystemManager.isSafePathName(pathName)) {
                            String errorString = "Path name is unsafe: File delete request failed";
                            String errorMsg = Protocol.createFileDeleteResponse(fileDescriptor, pathName, errorString, false).toJson();

                            sendPacket(errorMsg);

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg);

                        } else if (!fileSystemManager.deleteFile(pathName, fileDescriptor.lastModified, fileDescriptor.md5)) {
                            String errorString = "File doesn't exist: File delete request failed";
                            String errorMsg = Protocol.createFileDeleteResponse(fileDescriptor, pathName, errorString, false).toJson();

                            sendPacket(errorMsg);

                            log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg);

                        } else {
                            String messageString = "The file was deleted";
                            String fileDeleteMessage = Protocol.createFileDeleteResponse(fileDescriptor, pathName, messageString, true).toJson();

                            sendPacket(fileDeleteMessage);

                            log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(fileDeleteMessage);
                        }

                        break;
                    }

                    case "FILE_DELETE_RESPONSE": {
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);
                        String request = Protocol.createFileDeleteRequest(fileDescriptor, JSON.getString("pathName")).toJson();
                        if (!requestRecords.containsKey(request))
                            break;
                        requestRecords.remove(request);

                        log.info("[LocalPeer] A file delete response was received from " + clientHostPort.toString());

                        if (!JSON.getBoolean("status"))
                            log.info(String.format("[LocalPeer] Couldn't delete %s on %s because %s",
                                    JSON.getString("pathName"),
                                    clientHostPort.toString(),
                                    JSON.getString("message")));

                        break;
                    }

                    case"FILE_MODIFY_REQUEST": {
                        if (!handshakeCompleted)
                            break;

                        log.info("[LocalPeer] A file modify request was received from " + clientHostPort.toString());

                        String pathName = JSON.getString("pathName");
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);

                        try {
                            if (!fileSystemManager.isSafePathName(pathName)) {
                                String errorString = "Path name is unsafe: File modify request failed";
                                String errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false).toJson();

                                sendPacket(errorMsg);

                                log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                                log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                                log.info(errorMsg);

                            } else if (fileSystemManager.fileNameExists(pathName, fileDescriptor.md5)) {
                                String errorString = "File with the same content has existed: File modify request failed";
                                String errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false).toJson();

                                sendPacket(errorMsg);

                                log.info("[LocalPeer] File with the same content has existed, refused request from " + clientHostPort.toString());
                                log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                                log.info(errorMsg);

                            } else if (!fileSystemManager.modifyFileLoader(pathName, fileDescriptor.md5, fileDescriptor.fileSize, fileDescriptor.lastModified)) {
                                String errorString = "File doesn't exist: File modify request failed";
                                String errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false).toJson();

                                sendPacket(errorMsg);

                                log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
                                log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                                log.info(errorMsg);

                            } else {
                                String messageString = "Modify file loader ready";
                                String fileModifyMessage = Protocol.createFileModifyResponse(fileDescriptor, pathName, messageString, true).toJson();

                                sendPacket(fileModifyMessage);

                                log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                                log.info(fileModifyMessage);

                                sendFileBytesRequest(fileDescriptor, pathName, 0, fileDescriptor.fileSize);
                            }

                        } catch (IOException e) {
                            String errorString = "Cannot modify file loader as it has already been created";
                            log.info("[LocalPeer] Cannot modify the file loader, refused request from " + clientHostPort.toString());
                            String errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false).toJson();

                            sendPacket(errorMsg);
                        }

                        break;
                    }

                    case "FILE_MODIFY_RESPONSE": {
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);
                        String request = Protocol.createFileModifyRequest(fileDescriptor, JSON.getString("pathName")).toJson();
                        if (!requestRecords.containsKey(request))
                            break;
                        requestRecords.remove(request);

                        log.info("[LocalPeer] A file modify response was received from " + clientHostPort.toString());

                        if (!JSON.getBoolean("status"))
                            log.info(String.format("[LocalPeer] Couldn't modify %s on %s because %s",
                                    JSON.getString("pathName"),
                                    clientHostPort.toString(),
                                    JSON.getString("message")));

                        break;
                    }

                    case"DIRECTORY_CREATE_REQUEST": {
                        if (!handshakeCompleted)
                            break;

                        log.info("[LocalPeer] A directory create request was received from " + clientHostPort.toString());
                        String pathName = JSON.getString("pathName");

                        if (!fileSystemManager.isSafePathName(pathName)) {
                            String errorString = "Path name is unsafe: Directory create request failed";
                            String errorMsg = Protocol.createDirectoryCreateResponse(pathName, errorString, false).toJson();

                            sendPacket(errorMsg);

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg);

                        } else if (fileSystemManager.dirNameExists(pathName)) {
                            String errorString = "Directory name has existed: Directory create request failed";
                            String errorMsg = Protocol.createDirectoryCreateResponse(pathName, errorString, false).toJson();

                            sendPacket(errorMsg);

                            log.info("[LocalPeer] Directory name has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg);

                        } else {
                            fileSystemManager.makeDirectory(pathName);
                            String messageString = "Directory was created";
                            String directoryCreateMessage = Protocol.createDirectoryCreateResponse(pathName, messageString, true).toJson();

                            sendPacket(directoryCreateMessage);
                        }

                        break;
                    }

                    case"DIRECTORY_CREATE_RESPONSE": {
                        String request = Protocol.createDirectoryCreateRequest(JSON.getString("pathName")).toJson();
                        if (!requestRecords.containsKey(request))
                            break;
                        requestRecords.remove(request);

                        log.info("[LocalPeer] A directory create response was received from " + clientHostPort.toString());
                        break;
                    }

                    case"DIRECTORY_DELETE_REQUEST": {
                        if (!handshakeCompleted)
                            break;

                        log.info("[LocalPeer] A directory delete request was received from " + clientHostPort.toString());

                        String pathName = JSON.getString("pathName");
                        if (!fileSystemManager.isSafePathName(pathName)) {
                            String errorString = "Path name is unsafe: Directory delete request failed";
                            String errorMsg = Protocol.createDirectoryDeleteResponse(pathName, errorString, false).toJson();

                            sendPacket(errorMsg);

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg);

                        } else if (!fileSystemManager.dirNameExists(pathName)) {
                            String errorString = "Directory doesn't exist: Directory delete request failed";
                            String errorMsg = Protocol.createDirectoryDeleteResponse(pathName, errorString, false).toJson();

                            sendPacket(errorMsg);

                            log.info("[LocalPeer] Directory doesn't exist, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg);

                        } else {
                            fileSystemManager.deleteDirectory(pathName);
                            String messageString = "Directory was deleted";
                            String directoryDeleteMessage = Protocol.createDirectoryDeleteResponse(pathName, messageString, true).toJson();

                            sendPacket(directoryDeleteMessage);
                        }

                        break;
                    }

                    case"DIRECTORY_DELETE_RESPONSE": {
                        String request = Protocol.createDirectoryDeleteRequest(JSON.getString("pathName")).toJson();
                        if (!requestRecords.containsKey(request))
                            break;
                        requestRecords.remove(request);

                        log.info("[LocalPeer] A directory delete response was received from " + clientHostPort.toString());
                        break;
                    }
                }
            }
        } catch (SocketException | NullPointerException | InterruptedException e) {
            e.printStackTrace();

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();

        } finally {
            log.info("[LocalPeer] Unable to communicate with " + clientHostPort.toString() + ", disconnected!");
            localPeer.removeFromConnectedPeers(clientHostPort);
        }
    }
}