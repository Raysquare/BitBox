package unimelb.bitbox;

import unimelb.bitbox.util.BitboxKey;
import unimelb.bitbox.util.Configuration;
import unimelb.bitbox.util.FileSystemManager;
import unimelb.bitbox.util.HostPort;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.logging.Logger;

public class CommandServer {

    private int clientPort;
    private ArrayList<String> connectedPeers;
    private static final Logger log = Logger.getLogger(Peer.class.getName());
    private HashMap<String, String> keyList = new java.util.HashMap<String, String>();
    private PublicKey publicKey;

    public CommandServer() throws IOException, NoSuchAlgorithmException
    {
        connectedPeers = new ArrayList<>();
        clientPort = Integer.parseInt(Configuration.getConfigurationValue("clientPort").trim());
        String keys = Configuration.getConfigurationValue("authorized_keys");
        String[] splitKey = keys.trim().split(" ");

        //publicKey = BitboxKey.StringToPublicKey()
    }


}
