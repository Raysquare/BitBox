package unimelb.bitbox;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import unimelb.bitbox.util.Configuration;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager;
import unimelb.bitbox.util.Protocol;

public class Peer 
{
    private ArrayList<Document> protocolEventList;
    private ArrayList<Peer> peerList;

    public Peer(){

    }

	private static Logger log = Logger.getLogger(Peer.class.getName());
    public static void main( String[] args ) throws IOException, NumberFormatException, NoSuchAlgorithmException
    {
    	System.setProperty("java.util.logging.SimpleFormatter.format",
                "[%1$tc] %2$s %4$s: %5$s%n");
        log.info("BitBox Peer starting...");
        Configuration.getConfiguration();

        //peerA,peerB;
        //protocolEventList.add(Protocol.createHanfHakeRequest());
        //

        // while(true)
            // notifyAll
        new ServerMain();
        
    }

    public void NotifyAll(ArrayList<Protocol.PROTOCOL_COMMAND> protocolEventList, ArrayList<Peer> peerList ){
        // Implement 2 fors , iterate it

        // for (eventprotocolEventList)
        //      for (eventPeerList)
        //            sendProtocol(Peer,Event)
        //

    }

    public void sendProtocol(Peer peer, Protocol.PROTOCOL_COMMAND protocolCommand){
        //
    }
}
