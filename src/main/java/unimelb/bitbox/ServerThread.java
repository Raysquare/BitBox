package unimelb.bitbox;

import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;
import unimelb.bitbox.util.FileSystemObserver;
import unimelb.bitbox.util.HostPort;

import java.io.*;
import java.net.Socket;
import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;


public class ServerThread extends Thread implements FileSystemObserver
{
	private static final Logger log = Logger.getLogger(ServerThread.class.getName());
	private Peer localPeer;
	private Socket socket;
	private final BufferedReader input;
	private final BufferedWriter output;
	private HostPort serverHostPort;
	public HostPort clientHostPort;

	private boolean isFirstTime;
	
	public ServerThread(Peer localPeer, Socket socket, HostPort serverHostPort, HostPort clientHostPort) throws IOException
	{
		isFirstTime = true;
		this.socket = socket;
		this.localPeer = localPeer;
		this.serverHostPort = serverHostPort;
		this.clientHostPort = clientHostPort;
		input = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF8"));
		output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
	}

	public void sendHandshakeRequest() throws IOException
	{
		Document handshakeRequest = Protocol.createHandshakeRequest(serverHostPort);
		output.write(handshakeRequest.toJson());
		output.newLine();
		output.flush();
		log.info("[LocalPeer] Sent a handshake request to " + clientHostPort.toString());
		log.info(handshakeRequest.toJson());
	}

	public void processFileSystemEvent(FileSystemEvent fileSystemEvent)
	{
		try {
			switch (fileSystemEvent.event) {
				case FILE_CREATE:
					Document message = Protocol.createFileCreateRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName);
					synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A file create event was received");
					log.info("[LocalPeer] Sent FILE_CREATE_REQUEST to " + clientHostPort.toString());
					log.info(message.toJson());
					break;

				case FILE_DELETE:
					message = Protocol.createFileDeleteRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName);
					synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A file delete event was received");
					log.info("[LocalPeer] Sent FILE_DELETE_REQUEST to " + clientHostPort.toString());
					log.info(message.toJson());
					break;

				case FILE_MODIFY:
					message = Protocol.createFileModifyRequest(fileSystemEvent.fileDescriptor, fileSystemEvent.pathName);
					synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A file modify event has been received");
					log.info("[LocalPeer] Sent FILE_MODIFY_REQUEST to " + clientHostPort.toString());
					log.info(message.toJson());
					break;

				case DIRECTORY_CREATE:
					message = Protocol.createDirectoryCreateRequest(fileSystemEvent.pathName);
					synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A directory create event has been received");
					log.info("[LocalPeer] Sent DIRECTORY_CREATE_REQUEST to " + clientHostPort.toString());
					log.info(message.toJson());
					break;

				case DIRECTORY_DELETE:
					message = Protocol.createDirectoryDeleteRequest(fileSystemEvent.pathName);
					synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A directory delete event has been received");
					log.info("[LocalPeer] Sent DIRECTORY_DELETE_REQUEST to " + clientHostPort.toString());
					log.info(message.toJson());
					break;
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void close()
	{
		try {
			input.close();
			output.close();
			socket.close();

		} catch (IOException e) {
			log.info("[LocalPeer] Unable to close the socket connecting to " + clientHostPort.toString());
		} finally {
			localPeer.removeFromConnectedPeers(this);
		}
	}

	/*
		This method process all the protocol commands.
	 */
	public void run()
	{
		FileSystemManager fileSystemManager = localPeer.fileSystemManager;

		try {
			while (true) {
				Document JSON = Document.parse(input.readLine());
				//log.info(JSON.toJson());

				if (!Protocol.isValid(JSON)) {
					Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: the message misses required fields");
					synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A message missing required fields was received from " + clientHostPort.toString());
					log.info("[LocalPeer] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
					log.info(errorMsg.toJson());
					break;
				}

				switch (JSON.getString("command")) {
					case "HANDSHAKE_REQUEST":
						if (!isFirstTime) {
							Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: handshake has been completed");
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] Multiple handshakes were received from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							return;
						}

						if (localPeer.hasReachedMaxConnections()) {
							Document errorMsg = Protocol.createConnectionRefused("The maximum connections has been reached", localPeer.getConnectedPeerHostPort());
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] The maximum connections were reached, disconnected from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent CONNECTION_REFUSED to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							return;
						}

						Document message = Protocol.createHandshakeResponse(serverHostPort);
						synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}
						isFirstTime = false;

						log.info("[LocalPeer] A handshake request was received from " + clientHostPort.toString());
						log.info("[LocalPeer] Sent HANDSHAKE_RESPONSE to " + clientHostPort.toString());
						log.info((message.toJson()));
						break;

					case "HANDSHAKE_RESPONSE":
						log.info("[LocalPeer] A handshake response was received from " + clientHostPort.toString());
						break;

					case "CONNECTION_REFUSED":
						log.info("[LocalPeer] A connection refused message was received from " + clientHostPort.toString());
						//TODO: handle the rest of protocol commands
				}

			}
		} catch (IOException e) {
			log.info("[LocalPeer] Unable to communicate with " + clientHostPort.toString() + ", disconnected!");
		} finally {
			close();
		}
	}
}