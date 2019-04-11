package unimelb.bitbox.util;

public class Protocol {
    public enum PROTOCOL_COMMAND
    {
        HANDSHAKE_REQUEST,
        //...
    }

    public Document createFileRequest(FileSystemManager.FileDescriptor fileDescriptor, String pathName){
        return null;
    }

    public Document createHandshakeResponse(HostPort hostPort){
        return null;
    }

    // ....
}
