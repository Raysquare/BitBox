package unimelb.bitbox;

import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager.FileDescriptor;
import unimelb.bitbox.util.HostPort;

import java.util.ArrayList;

public class Protocol {
    public static enum Command {
        INVALID_PROTOCOL,
        CONNECTION_REFUSED,
        HANDSHAKE_REQUEST,
        HANDSHAKE_RESPONSE,
        FILE_CREATE_REQUEST,
        FILE_CREATE_RESPONSE,
        FILE_DELETE_REQUEST,
        FILE_DELETE_RESPONSE,
        FILE_MODIFY_REQUEST,
        FILE_MODIFY_RESPONSE,
        DIRECTORY_CREATE_REQUEST,
        DIRECTORY_CREATE_RESPONSE,
        DIRECTORY_DELETE_REQUEST,
        DIRECTORY_DELETE_RESPONSE,
        FILE_BYTES_REQUEST,
        FILE_BYTES_RESPONSE
    }

    public static boolean isValid(Document message)
    {
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

                //TODO: check the reset of the commands
        }

        return false; //delete this line after this method is implemented
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

    public static Document createHandshakeRequest(HostPort host) {
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

    public static Document createFileCreateRequest(FileDescriptor fileDescriptor, String pathName) {
        Document JSON = new Document();

        JSON.append("command", "FILE_CREATE_REQUEST");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);

        return JSON;
    }

    public static Document createFileCreateResponse(FileDescriptor fileDescriptor, String pathName, String message, boolean status) {
        Document JSON = new Document();

        JSON.append("command", "FILE_CREATE_RESPONSE");
        JSON.append("fileDescriptor", fileDescriptor.toDoc());
        JSON.append("pathName", pathName);
        JSON.append("message", message);
        JSON.append("status", status);

        return JSON;
    }

    //TODO: implementing the creation methods for the rest of commands
}