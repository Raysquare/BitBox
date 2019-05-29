package unimelb.bitbox;

import unimelb.bitbox.util.Configuration;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

public class Peer
{
    public static void main(String[] args) throws IOException, NumberFormatException, NoSuchAlgorithmException
    {
        System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tc] %2$s %4$s: %5$s%n");
        Logger log = Logger.getLogger(Peer.class.getName());
        log.info("BitBox Peer starting...");

        Server server;

        if (Configuration.getConfigurationValue("mode").trim().equals("tcp"))
            server = new TCPServer();
        else
            server = new UDPServer();


        CommandServer commandServer = new CommandServer(server);
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    commandServer.start();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();

        server.start();
    }
}