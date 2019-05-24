package unimelb.bitbox;

import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager;
import unimelb.bitbox.util.FileSystemManager.FileDescriptor;
import unimelb.bitbox.util.HostPort;

import javax.print.Doc;
import java.util.ArrayList;

public class Protocol {
    public static boolean isValid(Document message)
    {
        if (!message.containsKey("command"))
            return false;

        switch (message.getString("command")) {
            case "INVALID_PROTOCOL":
                return message.containsKey("message");

            case "CONNECTION_REFUSED":
                if (message.containsKey("message") && message.containsKey("peers")) {
                    for (Document peer : (ArrayList<Document>)message.get("peers")) {
                        if (!peer.containsKey("host") || !peer.containsKey("port"))
                            return false;
                    }
                    return true;
                }
                return false;

            case "HANDSHAKE_REQUEST":
            case "HANDSHAKE_RESPONSE":
                if (message.containsKey("hostPort")) {
                    Document hostPort = (Document)message.get("hostPort");
                    return hostPort.containsKey("host") && hostPort.containsKey("port");
                }
                return false;

            case "FILE_CREATE_REQUEST":
                if (message.containsKey("pathName") && message.containsKey("fileDescriptor")) {
                    Document fileDescriptor = (Document)message.get("fileDescriptor");
                    return fileDescriptor.containsKey("md5") &&
                            fileDescriptor.containsKey("lastModified") &&
                            fileDescriptor.containsKey("fileSize");
                }
                return false;

            case "FILE_CREATE_RESPONSE":
                if (message.containsKey("pathName") && message.containsKey("fileDescriptor") &&
                    message.containsKey("message") && message.containsKey("status")) {
                    Document fileDescriptor = (Document)message.get("fileDescriptor");
                    return fileDescriptor.containsKey("md5") &&
                            fileDescriptor.containsKey("lastModified") &&
                            fileDescriptor.containsKey("fileSize");
                }
                return false;

            case "FILE_BYTES_REQUEST":
                if (message.containsKey("pathName") && message.containsKey("fileDescriptor") &&
                        message.containsKey("position") && message.containsKey("length")) {
                    Document fileDescriptor = (Document)message.get("fileDescriptor");
                    return fileDescriptor.containsKey("md5") &&
                            fileDescriptor.containsKey("lastModified") &&
                            fileDescriptor.containsKey("fileSize");
                }
                return false;

            case "FILE_BYTES_RESPONSE":
                if (message.containsKey("pathName") && message.containsKey("fileDescriptor") &&
                        message.containsKey("position") && message.containsKey("length") &&
                        message.containsKey("content") && message.containsKey("message") && message.containsKey("status"))
                {
                    Document fileDescriptor = (Document)message.get("fileDescriptor");
                    return fileDescriptor.containsKey("md5") &&
                            fileDescriptor.containsKey("lastModified") &&
                            fileDescriptor.containsKey("fileSize");
                }
                return false;

            case "FILE_DELETE_REQUEST":
            case "FILE_MODIFY_REQUEST":
                if (message.containsKey("pathName") && message.containsKey("fileDescriptor"))
                {
                    Document fileDescriptor = (Document)message.get("fileDescriptor");
                    return fileDescriptor.containsKey("md5") &&
                            fileDescriptor.containsKey("lastModified") &&
                            fileDescriptor.containsKey("fileSize");
                }
                return false;

            case "FILE_DELETE_RESPONSE":
            case "FILE_MODIFY_RESPONSE":
                if (message.containsKey("pathName") && message.containsKey("fileDescriptor") &&
                        message.containsKey("message") && message.containsKey("status"))
                {
                    Document fileDescriptor = (Document)message.get("fileDescriptor");
                    return fileDescriptor.containsKey("md5") &&
                            fileDescriptor.containsKey("lastModified") &&
                            fileDescriptor.containsKey("fileSize");
                }
                return false;

            case "DIRECTORY_CREATE_REQUEST":
            case "DIRECTORY_DELETE_REQUEST":
                return message.containsKey("pathName");

            case "DIRECTORY_CREATE_RESPONSE":
            case "DIRECTORY_DELETE_RESPONSE":
                return (message.containsKey("pathName") && message.containsKey("message") && message.containsKey("status"));

            case "AUTH_REQUEST":
                return message.containsKey("identity");

            case "AUTH_RESPONSE":
                return (message.containsKey("AES128") && message.containsKey("status") && message.containsKey("message"));

            case "LIST_PEERS_REQUEST":
            case "LIST_PEERS_RESPONSE":
                if (message.containsKey("peers")) {
                    for (Document peer : (ArrayList<Document>)message.get("peers")) {
                        if (!peer.containsKey("host") || !peer.containsKey("port"))
                            return false;
                    }
                    return true;
                }
                return false;

            case "CONNECT_PEER_REQUEST":
            case "DISCONNECT_PEER_REQUEST":
                if (message.containsKey("hostPort")) {
                    Document hostPort = (Document)message.get("hostPort");
                    return hostPort.containsKey("host") && hostPort.containsKey("port");
                }
                return false;

            case "CONNECT_PEER_RESPONSE":
            case "DISCONNECT_PEER_RESPONSE":
                if (message.containsKey("hostPort") && message.containsKey("status") && message.containsKey("message")) {
                    Document hostPort = (Document)message.get("hostPort");
                    return hostPort.containsKey("host") && hostPort.containsKey("port");
                }
                return false;

        }

        return false;
    }

    public static Document createInvalidProtocol(String message)
    {
        Document JSON = new Document();

        JSON.append("command", "INVALID_PROTOCOL");
        JSON.append("message", message);

        return JSON;
    }

    public static Document createConnectionRefused(String message, ArrayList<Document> peers)
    {
        Document JSON = new Document();

        JSON.append("command", "CONNECTION_REFUSED");
        JSON.append("message", message);
        JSON.append("peers", peers);

        return JSON;
    }

    public static Document createHandshakeRequest(HostPort host)
    {
        Document JSON = new Document();

        JSON.append("command", "HANDSHAKE_REQUEST");
        JSON.append("hostPort", host.toDoc());

        return JSON;
    }

    public static Document createHandshakeResponse(HostPort host)
    {
        Document JSON = new Document();

        JSON.append("command", "HANDSHAKE_RESPONSE");
        JSON.append("hostPort", host.toDoc());

        return JSON;
    }

    public static Document createFileCreateRequest(FileDescriptor fileDescriptor, String pathName)
    {
        Document JSON = new Document();

        JSON.append("command", "FILE_CREATE_REQUEST");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);

        return JSON;
    }

    public static Document createFileCreateResponse(FileDescriptor fileDescriptor, String pathName, String message, boolean status)
    {
        Document JSON = new Document();

        JSON.append("command", "FILE_CREATE_RESPONSE");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);
        JSON.append("message", message);
        JSON.append("status", status);

        return JSON;
    }

    public static Document createFileBytesRequest(FileDescriptor fileDescriptor, String pathName, long position, long length){
        Document JSON = new Document();

        JSON.append("command", "FILE_BYTES_REQUEST");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);
        JSON.append("position", position);
        JSON.append("length", length);

        return JSON;
    }

    public static Document createFileBytesResponse(FileDescriptor fileDescriptor, String pathName, long position, long length, String content, String message, boolean status)
    {
        Document JSON = new Document();

        JSON.append("command", "FILE_BYTES_RESPONSE");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);
        JSON.append("position", position);
        JSON.append("length", length);
        JSON.append("content", content);
        JSON.append("message", message);
        JSON.append("status", status);

        return JSON;
    }

    public static Document createFileDeleteRequest(FileDescriptor fileDescriptor, String pathName)
    {
        Document JSON = new Document();

        JSON.append("command", "FILE_DELETE_REQUEST");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);

        return JSON;
    }

    public static Document createFileDeleteResponse(FileDescriptor fileDescriptor, String pathName, String message, boolean status)
    {
        Document JSON = new Document();

        JSON.append("command", "FILE_DELETE_RESPONSE");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);
        JSON.append("message", message);
        JSON.append("status", status);

        return JSON;
    }

    public static Document createFileModifyRequest(FileDescriptor fileDescriptor, String pathName)
    {
        Document JSON = new Document();

        JSON.append("command", "FILE_MODIFY_REQUEST");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);

        return JSON;
    }

    public static Document createFileModifyResponse(FileDescriptor fileDescriptor, String pathName, String message, boolean status)
    {
        Document JSON = new Document();

        JSON.append("command", "FILE_MODIFY_RESPONSE");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);
        JSON.append("message", message);
        JSON.append("status", status);

        return JSON;
    }

    public static Document createDirectoryCreateRequest(String pathName)
    {
        Document JSON = new Document();

        JSON.append("command", "DIRECTORY_CREATE_REQUEST");
        JSON.append("pathName", pathName);

        return JSON;
    }

    public static Document createDirectoryCreateResponse(String pathName, String message, boolean status)
    {
        Document JSON = new Document();

        JSON.append("command", "DIRECTORY_CREATE_RESPONSE");
        JSON.append("pathName", pathName);
        JSON.append("message", message);
        JSON.append("status", status);

        return JSON;
    }

    public static Document createDirectoryDeleteRequest(String pathName)
    {
        Document JSON = new Document();

        JSON.append("command", "DIRECTORY_DELETE_REQUEST");
        JSON.append("pathName", pathName);

        return JSON;
    }

    public static Document createDirectoryDeleteResponse(String pathName, String message, boolean status)
    {
        Document JSON = new Document();

        JSON.append("command", "DIRECTORY_DELETE_RESPONSE");
        JSON.append("pathName", pathName);
        JSON.append("message", message);
        JSON.append("status", status);

        return JSON;
    }

    public static FileDescriptor createFileDescriptorFromDocument(FileSystemManager fileSystemManager, Document JSON)
    {
        Document fileDescriptor =(Document) JSON.get("fileDescriptor");
        long lastModified = fileDescriptor.getLong("lastModified");
        long fileSize = fileDescriptor.getLong("fileSize");
        String md5 = fileDescriptor.getString("md5");

        return fileSystemManager.new FileDescriptor(lastModified, md5, fileSize);
    }

    public static Document createAuthorizationRequest(String identity)
    {
        Document JSON = new Document();

        JSON.append("command", "AUTH_REQUEST");
        JSON.append("identity", identity);

        return JSON;
    }

    public static Document createAuthorizationResponse(String secretKey, boolean status, String message)
    {
        Document JSON = new Document();

        JSON.append("command", "AUTH_RESPONSE");
        JSON.append("AES128", secretKey);
        JSON.append("status", status);
        JSON.append("message", message);

        return JSON;
    }

    public static Document createAuthorizationResponse(boolean status, String message)
    {
        Document JSON = new Document();

        JSON.append("command", "AUTH_RESPONSE");
        JSON.append("status", status);
        JSON.append("message", message);

        return JSON;
    }
    public static Document createPayload(String encryptedMessage)
    {
        Document JSON = new Document();

        JSON.append("payload", encryptedMessage);

        return JSON;
    }

    public static Document createListPeerRequest()
    {
        Document JSON = new Document();

        JSON.append("command", "LIST_PEERS_REQUEST");

        return JSON;
    }

    public static Document createListPeerResponse(ArrayList<Document> peers)
    {
        Document JSON = new Document();

        JSON.append("command", "LIST_PEERS_RESPONSE");
        JSON.append("peers", peers);

        return JSON;
    }

    public static Document createConnectPeerRequest(HostPort host)
    {
        Document JSON = new Document();

        JSON.append("command", "CONNECT_PEER_REQUEST");
        JSON.append("hostPort", host.toDoc());

        return JSON;
    }

    public static Document createConnectPeerResponse(HostPort host, boolean status, String message)
    {
        Document JSON = new Document();

        JSON.append("command", "CONNECT_PEER_RESPONSE");
        JSON.append("hostPort", host.toDoc());
        JSON.append("status", status);
        JSON.append("message", message);

        return JSON;
    }

    public static Document createDisconnectPeerRequest(HostPort host)
    {
        Document JSON = new Document();

        JSON.append("command", "DISCONNECT_PEER_REQUEST");
        JSON.append("hostPort", host.toDoc());

        return JSON;
    }

    public static Document createDisconnectPeerResponse(HostPort host, boolean status, String message)
    {
        Document JSON = new Document();

        JSON.append("command", "DISCONNECT_PEER_RESPONSE");
        JSON.append("hostPort", host.toDoc());
        JSON.append("status", status);
        JSON.append("message", message);

        return JSON;
    }
}




