package unimelb.bitbox;

import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager;
import unimelb.bitbox.util.FileSystemManager.FileDescriptor;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;
import unimelb.bitbox.util.FileSystemObserver;
import unimelb.bitbox.util.HostPort;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedList;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Logger;


// Each connection will have a server thread associated with it.
public class TCPServerThread extends Thread implements FileSystemObserver
{
    private static final Logger log = Logger.getLogger(TCPServerThread.class.getName());
    private TCPServer localPeer; // the delegate object to the Peer instance
    private Socket socket;
    private BufferedReader input;
    private BufferedWriter output;
    private HostPort serverHostPort;
    private HostPort clientHostPort; // the host port that is used by client to connect to the local peer
    public HostPort clientSideServerHostPort; // the server host port on the client side

    public boolean handshakeCompleted;
    private LinkedList<HostPort> peerCandidates; // it is used to store peer list when receiving CONNECTION_REFUSED
    private ConcurrentLinkedQueue<String> messageQueue;

    private SenderThread senderThread;

    /*
        This is a dedicated thread used for sending all outgoing messages to the corresponding peer.
        This is the only thread that need to use the output object.
     */
    class SenderThread extends Thread {
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

                        output.write(message);
                        output.newLine();
                        output.flush();
                    }

                } catch (SocketException e) {
                } catch (IOException e) {}
            }
        }
    }

    public TCPServerThread(TCPServer localPeer, Socket socket, HostPort serverHostPort, HostPort clientHostPort) throws IOException
    {
        handshakeCompleted = false;
        this.socket = socket;
        this.localPeer = localPeer;
        this.serverHostPort = serverHostPort;
        this.clientHostPort = clientHostPort;

        input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

        peerCandidates = new LinkedList<>();
        messageQueue = new ConcurrentLinkedQueue<>();

        senderThread = new SenderThread();
        senderThread.start();
    }

    public void sendHandshakeRequest()
    {
        Document handshakeRequest = Protocol.createHandshakeRequest(serverHostPort);

        messageQueue.offer(handshakeRequest.toJson());
        log.info("[LocalPeer] Sent a handshake request to " + clientHostPort.toString());
        log.info(handshakeRequest.toJson());
    }

    public void sendFileBytesRequest(FileDescriptor fileDescriptor, String pathName, long position, long size)
    {
        long length = Math.min(localPeer.blockSize, size);
        Document fileByteMessage = Protocol.createFileBytesRequest(fileDescriptor, pathName, position, length);

        messageQueue.offer(fileByteMessage.toJson());
        log.info("[LocalPeer] Sent FILE_BYTES_REQUEST to " + clientHostPort.toString());
        log.info((fileByteMessage.toJson()));
    }

    /*
        This methods creates corresponding messages when receiving file system events
     */
    public void processFileSystemEvent(FileSystemEvent fileSystemEvent)
    {
        if (!handshakeCompleted)
            return;

        Document message = localPeer.fileSystemEventHandler(fileSystemEvent, clientHostPort);
        messageQueue.offer(message.toJson());
    }

    private void close()
    {
        try {
            input.close();
            output.close();
            socket.close();

        } catch (IOException e) {
            log.info("[LocalPeer] Unable to close the socket connecting to " + clientHostPort.toString());
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
                Document JSON = Document.parse(input.readLine());
                //log.info(JSON.toJson());

                if (!Protocol.isValid(JSON)) {
                    Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: the message misses required fields");
                    messageQueue.offer(errorMsg.toJson());

                    log.info("[LocalPeer] A message missing required fields was received from " + clientHostPort.toString());
                    log.info("[LocalPeer] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
                    log.info(errorMsg.toJson());
                    break;
                }

                switch (JSON.getString("command")) {
                    case "HANDSHAKE_REQUEST": {
                        if (handshakeCompleted) {
                            Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: handshake has been completed");
                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Multiple handshakes were received from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());
                            return;
                        }

                        // store the host port sent from the peer
                        Document hostPort = (Document)JSON.get("hostPort");
                        clientSideServerHostPort = new HostPort(hostPort.getString("host").trim(), (int)hostPort.getLong("port"));

                        if (localPeer.hasReachedMaxConnections()) {
                            String errorString = "The maximum connections has been reached";
                            Document errorMsg = Protocol.createConnectionRefused(errorString, localPeer.getConnectedPeerHostPort(clientSideServerHostPort));
                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] The maximum connections were reached, disconnected from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent CONNECTION_REFUSED to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());
                            return;
                        }

                        Document message = Protocol.createHandshakeResponse(serverHostPort);
                        messageQueue.offer(message.toJson());

                        handshakeCompleted = true;

                        log.info("[LocalPeer] A handshake request was received from " + clientHostPort.toString());
                        log.info("[LocalPeer] Sent HANDSHAKE_RESPONSE to " + clientHostPort.toString());
                        log.info((message.toJson()));

                        for (FileSystemEvent event : fileSystemManager.generateSyncEvents())
                            processFileSystemEvent(event);

                        break;
                    }

                    case "HANDSHAKE_RESPONSE": {
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

                        // get peers needed to try from the peer list
                        for (Document peer : (ArrayList<Document>)JSON.get("peers")) {
                            HostPort peerHostPort = new HostPort(peer.getString("host"), (int)peer.getLong("port"));

                            // remove duplicated peers
                            if (!peerCandidates.contains(peerHostPort))
                                peerCandidates.offer(peerHostPort);
                        }

                        do {
                            // if there is no peer to connect, then closes the thread
                            if (peerCandidates.isEmpty())
                                return;

                            // get a peer to connect
                            clientHostPort = peerCandidates.poll();

                            try {
                                log.info("[LocalPeer] Trying to connect to " + clientHostPort.toString());
                                Socket newSocket = new Socket(clientHostPort.host, clientHostPort.port);

                                // the peer is successfully connected, close the current socket and get new socket
                                close();
                                input = new BufferedReader(new InputStreamReader(newSocket.getInputStream(), StandardCharsets.UTF_8));
                                output = new BufferedWriter(new OutputStreamWriter(newSocket.getOutputStream(), StandardCharsets.UTF_8));
                                socket = newSocket;

                                sendHandshakeRequest();
                                break;

                            } catch (IOException e) {
                                log.info("[LocalPeer] Failed to connect to " + clientHostPort.toString());
                            }

                        } while (true);

                        break;
                    }

                    case "FILE_CREATE_REQUEST": {
                        if (!handshakeCompleted)
                            break;

                        log.info("[LocalPeer] A file create request was received from " + clientHostPort.toString());

                        String pathName = JSON.getString("pathName");
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);

                        if (!fileSystemManager.isSafePathName(pathName)) {
                            String errorString = "Path name is unsafe: File create request failed";
                            Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                            // if the file with the same content exists, then reject the request
                        } else if (fileSystemManager.fileNameExists(pathName, fileDescriptor.md5)) {
                            String errorString = "File with the same content has existed: File create request failed";
                            Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] File with the same content has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                            // if the file exists but with different content, then try to modify it
                        } else if (fileSystemManager.fileNameExists(pathName)) {

                            // if the file is newer, then reject the request, otherwise overwrite the current older file
                            if (!fileSystemManager.modifyFileLoader(pathName, fileDescriptor.md5, fileDescriptor.fileSize, fileDescriptor.lastModified)) {
                                String errorString = "There is a newer version: File create request failed";
                                Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

                                messageQueue.offer(errorMsg.toJson());

                                log.info("[LocalPeer] There is a newer version, refused request from " + clientHostPort.toString());
                                log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                log.info(errorMsg.toJson());

                            } else {
                                String messageString = "Overwrite the older version";
                                Document message = Protocol.createFileCreateResponse(fileDescriptor, pathName, messageString, true);

                                messageQueue.offer(message.toJson());

                                log.info("[LocalPeer] Overwrite the older version and get a new one from " + clientHostPort.toString());
                                log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                log.info(message.toJson());
                                sendFileBytesRequest(fileDescriptor, pathName, 0, fileDescriptor.fileSize);
                            }

                        } else {
                            try {
                                fileSystemManager.createFileLoader(pathName, fileDescriptor.md5, fileDescriptor.fileSize, fileDescriptor.lastModified);

                                // if there is a file with a different name but the same content, then reject the request, otherwise then the request is accepted
                                if (fileSystemManager.checkShortcut(pathName)) {
                                    String errorString = "There is a file with the same content, no need to transfer it again.";
                                    log.info("[LocalPeer] There is a file with the same content, no need to transfer it again from " + clientHostPort.toString());
                                    Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

                                    messageQueue.offer(errorMsg.toJson());
                                    break;
                                }

                                String messageString = "File loader ready";
                                Document fileCreateMessage = Protocol.createFileCreateResponse(fileDescriptor, pathName, messageString, true);

                                messageQueue.offer(fileCreateMessage.toJson());

                                log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                                log.info(fileCreateMessage.toJson());

                                sendFileBytesRequest(fileDescriptor, pathName, 0, fileDescriptor.fileSize);

                            } catch (IOException e) {
                                String errorString = "Cannot create the file loader as it has already been created";
                                log.info("[LocalPeer] Cannot create the file loader, refused request from " + clientHostPort.toString());
                                Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

                                messageQueue.offer(errorMsg.toJson());
                            }
                        }

                        break;
                    }


                    case "FILE_CREATE_RESPONSE": {
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
                        long length = JSON.getLong("length");
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);

                        byte[] bytes = fileSystemManager.readFile(fileDescriptor.md5, position, length).array();
                        String content = Base64.getEncoder().encodeToString(bytes);
                        Document fileBytesMessage = Protocol.createFileBytesResponse(fileDescriptor, pathName, position, length, content, "successful read", true);

                        messageQueue.offer(fileBytesMessage.toJson());

                        log.info("[LocalPeer] Sent FILE_BYTES_RESPONSE success to " + clientHostPort.toString());
                        log.info((fileBytesMessage.toJson()));

                        break;
                    }

                    case"FILE_BYTES_RESPONSE": {
                        log.info("[LocalPeer] A file bytes response was received from " + clientHostPort.toString());

                        String pathName = JSON.getString("pathName");
                        FileDescriptor fileDescriptor = Protocol.createFileDescriptorFromDocument(fileSystemManager, JSON);
                        long length = JSON.getLong("length");
                        long position = JSON.getLong("position");

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
                            Document errorMsg = Protocol.createFileDeleteResponse(fileDescriptor, pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else if (!fileSystemManager.deleteFile(pathName, fileDescriptor.lastModified, fileDescriptor.md5)) {
                            String errorString = "File doesn't exist: File delete request failed";
                            Document errorMsg = Protocol.createFileDeleteResponse(fileDescriptor, pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else {
                            String messageString = "The file was deleted";
                            Document fileDeleteMessage = Protocol.createFileDeleteResponse(fileDescriptor, pathName, messageString, true);

                            messageQueue.offer(fileDeleteMessage.toJson());

                            log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(fileDeleteMessage.toJson());
                        }

                        break;
                    }

                    case "FILE_DELETE_RESPONSE": {
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

                         if (!fileSystemManager.isSafePathName(pathName)) {
                            String errorString = "Path name is unsafe: File modify request failed";
                            Document errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false);

                             messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else if (fileSystemManager.fileNameExists(pathName, fileDescriptor.md5)) {
                            String errorString = "File with the same content has existed: File modify request failed";
                            Document errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] File with the same content has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else if (!fileSystemManager.modifyFileLoader(pathName, fileDescriptor.md5, fileDescriptor.fileSize, fileDescriptor.lastModified)) {
                            String errorString = "File doesn't exist: File modify request failed";
                            Document errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else {
                            String messageString = "Modify file loader ready";
                            Document fileModifyMessage = Protocol.createFileModifyResponse(fileDescriptor, pathName, messageString, true);

                            messageQueue.offer(fileModifyMessage.toJson());

                            log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
                            log.info(fileModifyMessage.toJson());

                            sendFileBytesRequest(fileDescriptor, pathName, 0, fileDescriptor.fileSize);
                        }

                        break;
                    }

                    case "FILE_MODIFY_RESPONSE": {
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
                            Document errorMsg = Protocol.createDirectoryCreateResponse(pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else if (fileSystemManager.dirNameExists(pathName)) {
                            String errorString = "Directory name has existed: Directory create request failed";
                            Document errorMsg = Protocol.createDirectoryCreateResponse(pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Directory name has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else {
                            fileSystemManager.makeDirectory(pathName);
                            String messageString = "Directory was created";
                            Document directoryCreateMessage = Protocol.createDirectoryCreateResponse(pathName, messageString, true);

                            messageQueue.offer(directoryCreateMessage.toJson());
                        }

                        break;
                    }

                    case"DIRECTORY_CREATE_RESPONSE": {
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
                            Document errorMsg = Protocol.createDirectoryDeleteResponse(pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else if (!fileSystemManager.dirNameExists(pathName)) {
                            String errorString = "Directory doesn't exist: Directory delete request failed";
                            Document errorMsg = Protocol.createDirectoryDeleteResponse(pathName, errorString, false);

                            messageQueue.offer(errorMsg.toJson());

                            log.info("[LocalPeer] Directory doesn't exist, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());

                        } else {
                            fileSystemManager.deleteDirectory(pathName);
                            String messageString = "Directory was deleted";
                            Document directoryDeleteMessage = Protocol.createDirectoryDeleteResponse(pathName, messageString, true);

                            messageQueue.offer(directoryDeleteMessage.toJson());
                        }

                        break;
                    }

                    case"DIRECTORY_DELETE_RESPONSE": {
                        log.info("[LocalPeer] A directory delete response was received from " + clientHostPort.toString());
                        break;
                    }
                }

            }
        } catch (SocketException | NullPointerException e) {
            log.info("[LocalPeer] Unable to communicate with " + clientHostPort.toString() + ", disconnected!");

        } catch (IOException | NoSuchAlgorithmException e) {
            log.info("[LocalPeer] Unable to communicate with " + clientHostPort.toString() + ", disconnected!");

        } finally {
            localPeer.removeFromConnectedPeers(this);

            try {
                senderThread.interrupt();
                senderThread.join();

            } catch (InterruptedException v) {}

            close();
        }
    }
}