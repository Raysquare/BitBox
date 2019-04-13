package unimelb.bitbox;

import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;
import unimelb.bitbox.util.FileSystemObserver;
import unimelb.bitbox.util.HostPort;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.logging.Logger;


public class ServerMain extends Thread implements FileSystemObserver
{
	private static Logger log = Logger.getLogger(ServerMain.class.getName());
	private Peer localPeer;
	private Socket socket;
	private DataInputStream input;
	private DataOutputStream output;
	private HostPort serverHostPort;
	public HostPort clientHostPort;

	private boolean isFirstTime;
	
	public ServerMain(Peer localPeer, Socket socket, HostPort serverHostPort, HostPort clientHostPort) throws IOException
	{
		isFirstTime = true;
		this.socket = socket;
		this.localPeer = localPeer;
		this.serverHostPort = serverHostPort;
		this.clientHostPort = clientHostPort;
		input = new DataInputStream(socket.getInputStream());
		output = new DataOutputStream(socket.getOutputStream());

		start(); // start the thread
	}

	public void processFileSystemEvent(FileSystemEvent fileSystemEvent)
	{
		synchronized (output) {
			try {
				switch (fileSystemEvent.event) {
					case FILE_CREATE:
						Document message = Protocol.createFileCreateRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName);
						output.writeUTF(message.toJson());
						break;

					//TODO: handle the rest of file system event
				}

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void close() throws IOException
	{
		input.close();
		output.close();;
		socket.close();
		localPeer.removeFromConnectedPeers(this);
	}

	/*
		This method process all the protocol commands.
	 */
	public void run()
	{
		FileSystemManager fileSystemManager = localPeer.fileSystemManager;

		try {
			while (true) {
				Document JSON = Document.parse(input.readUTF());


				if (Protocol.isValid(JSON)) {
					log.info("Invalid protocol: the message misses required fields" + clientHostPort.toString());
					Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: the message misses required fields");
					synchronized (output) {output.writeUTF(errorMsg.toJson());}
					close();
					break;
				}

				switch (JSON.getString("command")) {
					case "HANDSHAKE_REQUEST":
						if (!isFirstTime) {
							log.info("Invalid protocol: handshake has been completed: " + clientHostPort.toString());
							Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: handshake has been completed");
							synchronized (output) {output.writeUTF(errorMsg.toJson());}
							close();
							return;
						}

						if (localPeer.hasReachedMaxConnections()) {
							log.info("The maximum connections has been reached: " + clientHostPort.toString());
							Document errorMsg = Protocol.createConnectionRefused("The maximum connections has been reached", localPeer.getConnectedPeerHostPort());
							synchronized (output) {output.writeUTF(errorMsg.toJson());}
							close();
							return;
						}

						log.info("A handshake request has been received: " + clientHostPort.toString());
						Document message = Protocol.createHandshakeResponse(serverHostPort);
						synchronized (output) {output.writeUTF(message.toJson());}
						isFirstTime = false;
						break;

					case "HANDSHAKE_RESPONSE":
						log.info("A handshake response has been received: " + clientHostPort.toString());
						break;

					case "CONNECTION_REFUSED":
						log.info("A connection refused message has been received: " + clientHostPort.toString());
						//TODO: handle the rest of protocol commands
				}

			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
