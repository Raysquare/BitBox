package unimelb.bitbox;

import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.FileSystemManager;
import unimelb.bitbox.util.FileSystemManager.FileDescriptor;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;
import unimelb.bitbox.util.FileSystemObserver;
import unimelb.bitbox.util.HostPort;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
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

    public void sendFileBytesRequest(FileDescriptor fileDescriptor, String pathName) throws IOException
    {
        long length = Math.min(localPeer.blockSize, fileDescriptor.fileSize);
        Document fileByteMessage = Protocol.createFileBytesRequest(fileDescriptor, pathName, 0, length);
        synchronized (output) {
            output.write(fileByteMessage.toJson());
            output.newLine();
            output.flush();
        }
        log.info("[LocalPeer] Sent FILE_BYTES_REQUEST to " + clientHostPort.toString());
        log.info((fileByteMessage.toJson()));
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

					log.info("[LocalPeer] A file modify event was received");
					log.info("[LocalPeer] Sent FILE_MODIFY_REQUEST to " + clientHostPort.toString());
					log.info(message.toJson());
					break;

				case DIRECTORY_CREATE:
					message = Protocol.createDirectoryCreateRequest(fileSystemEvent.pathName);
					synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A directory create event was received");
					log.info("[LocalPeer] Sent DIRECTORY_CREATE_REQUEST to " + clientHostPort.toString());
					log.info(message.toJson());
					break;

				case DIRECTORY_DELETE:
					message = Protocol.createDirectoryDeleteRequest(fileSystemEvent.pathName);
					synchronized (output) {output.write(message.toJson()); output.newLine(); output.flush();}

					log.info("[LocalPeer] A directory delete event was received");
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
					case "HANDSHAKE_REQUEST": {
						if (!isFirstTime) {
							Document errorMsg = Protocol.createInvalidProtocol("Invalid protocol: handshake has been completed");
							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Multiple handshakes were received from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent INVALID_PROTOCOL to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							return;
						}

						if (localPeer.hasReachedMaxConnections()) {
							Document errorMsg = Protocol.createConnectionRefused("The maximum connections has been reached", localPeer.getConnectedPeerHostPort());
							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] The maximum connections were reached, disconnected from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent CONNECTION_REFUSED to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							return;
						}

						Document message = Protocol.createHandshakeResponse(serverHostPort);
						synchronized (output) {
							output.write(message.toJson());
							output.newLine();
							output.flush();
						}
						isFirstTime = false;

						log.info("[LocalPeer] A handshake request was received from " + clientHostPort.toString());
						log.info("[LocalPeer] Sent HANDSHAKE_RESPONSE to " + clientHostPort.toString());
						log.info((message.toJson()));
						break;
					}

					case "HANDSHAKE_RESPONSE":
						log.info("[LocalPeer] A handshake response was received from " + clientHostPort.toString());
						break;

					case "CONNECTION_REFUSED":
						log.info("[LocalPeer] A connection refused message was received from " + clientHostPort.toString());

						//TODO: handle the rest of protocol commands
                        break;

                    case "FILE_CREATE_REQUEST": {
						log.info("[LocalPeer] A file create request was received from " + clientHostPort.toString());

						String pathName = JSON.getString("pathName");
						FileDescriptor fileDescriptor = Protocol.createFileDesctiptorFromDocument(fileSystemManager, JSON);

						if (!fileSystemManager.isSafePathName(pathName)) {
							String errorString = "Path name is unsafe: File create request failed";
							Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						if (fileSystemManager.fileNameExists(pathName)) {
							String errorString = "File name has existed: File create request failed";
							Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						fileSystemManager.createFileLoader(pathName, fileDescriptor.md5, fileDescriptor.fileSize, fileDescriptor.lastModified);

						if (fileSystemManager.checkShortcut(pathName)) {
							String errorString = "There is a file with the same content, no need to transfer it again.";
							log.info("[LocalPeer] There is a file with the same content, no need to transfer it again from " + clientHostPort.toString());
							Document errorMsg = Protocol.createFileCreateResponse(fileDescriptor, pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}
							break;
						}

						String messageString = "File loader ready";
						Document fileCreateMessage = Protocol.createFileCreateResponse(fileDescriptor, pathName, messageString, true);

						synchronized (output) {
							output.write(fileCreateMessage.toJson());
							output.newLine();
							output.flush();
						}

						log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
						log.info(fileCreateMessage.toJson());

                        sendFileBytesRequest(fileDescriptor, pathName);
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
						String pathName = JSON.getString("pathName");
						long position = JSON.getLong("position");
						long length = JSON.getLong("length");
						FileDescriptor fileDescriptor = Protocol.createFileDesctiptorFromDocument(fileSystemManager, JSON);

						byte[] bytes = fileSystemManager.readFile(fileDescriptor.md5, position, length).array();
						String content = Base64.getEncoder().encodeToString(bytes);
						Document fileBytesMessage = Protocol.createFileBytesResponse(fileDescriptor, pathName, position, length, content, "successful read", true);

						synchronized (output) {
							output.write(fileBytesMessage.toJson());
							output.newLine();
							output.flush();
						}

						log.info("[LocalPeer] A file bytes request was received from " + clientHostPort.toString());
						log.info("[LocalPeer] Sent FILE_BYTES_RESPONSE success to " + clientHostPort.toString());
						log.info((fileBytesMessage.toJson()));

						break;
					}

					case"FILE_BYTES_RESPONSE": {
                        log.info("[LocalPeer] A file bytes response was received from " + clientHostPort.toString());

						String pathName = JSON.getString("pathName");
						FileDescriptor fileDescriptor = Protocol.createFileDesctiptorFromDocument(fileSystemManager, JSON);
                        long length = JSON.getLong("length");
                        long position = JSON.getLong("position");

						byte[] bytes = Base64.getDecoder().decode(JSON.getString("content"));
						ByteBuffer content = ByteBuffer.wrap(bytes);

						fileSystemManager.writeFile(pathName, content, JSON.getLong("position"));

                        position += length;
                        length = Math.min(fileDescriptor.fileSize - position, length);

						if (!fileSystemManager.checkWriteComplete(pathName)) {
							Document fileByteMessage = Protocol.createFileBytesRequest(fileDescriptor, pathName, position, length);

							synchronized (output) {
								output.write(fileByteMessage.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Sent FILE_BYTES_REQUEST to " + clientHostPort.toString());
							log.info((fileByteMessage.toJson()));
						}

						break;
					}

					case"FILE_DELETE_REQUEST": {
						log.info("[LocalPeer] A file delete request was received from " + clientHostPort.toString());

						String pathName = JSON.getString("pathName");
						FileDescriptor fileDescriptor = Protocol.createFileDesctiptorFromDocument(fileSystemManager, JSON);

						if (!fileSystemManager.isSafePathName(pathName)) {
							String errorString = "Path name is unsafe: File delete request failed";
							Document errorMsg = Protocol.createFileDeleteResponse(fileDescriptor, pathName, errorString, false);
							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						if (!fileSystemManager.deleteFile(pathName, fileDescriptor.lastModified, fileDescriptor.md5)) {
							String errorString = "File doesn't exist: File delete request failed";
							Document errorMsg = Protocol.createFileDeleteResponse(fileDescriptor, pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						String messageString = "The file was deleted";
						Document fileDeleteMessage = Protocol.createFileDeleteResponse(fileDescriptor, pathName, messageString, true);

						synchronized (output) {
							output.write(fileDeleteMessage.toJson());
							output.newLine();
							output.flush();
						}

						log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
						log.info(fileDeleteMessage.toJson());

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
						log.info("[LocalPeer] A file modify request was received from " + clientHostPort.toString());

						String pathName = JSON.getString("pathName");
						FileDescriptor fileDescriptor = Protocol.createFileDesctiptorFromDocument(fileSystemManager, JSON);

						if (!fileSystemManager.isSafePathName(pathName)) {
							String errorString = "Path name is unsafe: File modify request failed";
							Document errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						if (!fileSystemManager.modifyFileLoader(pathName, fileDescriptor.md5, fileDescriptor.lastModified)) {
							String errorString = "File doesn't exist: File modify request failed";
							Document errorMsg = Protocol.createFileModifyResponse(fileDescriptor, pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						String messageString = "Modify file loader ready";
						Document fileModifyMessage = Protocol.createFileModifyResponse(fileDescriptor, pathName, messageString, true);

						synchronized (output) {
							output.write(fileModifyMessage.toJson());
							output.newLine();
							output.flush();
						}

						log.info("[LocalPeer] Sent FILE_MODIFY_REQUEST to " + clientHostPort.toString());
						log.info(fileModifyMessage.toJson());

                        sendFileBytesRequest(fileDescriptor, pathName);
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
						log.info("[LocalPeer] A directory create request was received from " + clientHostPort.toString());
						String pathName = JSON.getString("pathName");

						if (!fileSystemManager.isSafePathName(pathName)) {
							String errorString = "Path name is unsafe: Directory create request failed";
							Document errorMsg = Protocol.createDirectoryCreateResponse(pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						if (fileSystemManager.dirNameExists(pathName)) {
							String errorString = "Directory name has existed: Directory create request failed";
							Document errorMsg = Protocol.createDirectoryCreateResponse(pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Directory name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						fileSystemManager.makeDirectory(pathName);
						String messageString = "Directory was created";
						Document directoryCreateMessage = Protocol.createDirectoryCreateResponse(pathName, messageString, true);

						synchronized (output) {
							output.write(directoryCreateMessage.toJson());
							output.newLine();
							output.flush();
						}

						break;
					}

					case"DIRECTORY_CREATE_RESPONSE": {
						log.info("[LocalPeer] A directory create response was received from " + clientHostPort.toString());
						break;
					}

					case"DIRECTORY_DELETE_REQUEST": {
						log.info("[LocalPeer] A directory delete request was received from " + clientHostPort.toString());

						String pathName = JSON.getString("pathName");
						if (!fileSystemManager.isSafePathName(pathName)) {
							String errorString = "Path name is unsafe: Directory delete request failed";
							Document errorMsg = Protocol.createDirectoryDeleteResponse(pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						if (!fileSystemManager.dirNameExists(pathName)) {
							String errorString = "Directory doesn't exist: Directory delete request failed";
							Document errorMsg = Protocol.createDirectoryDeleteResponse(pathName, errorString, false);

							synchronized (output) {
								output.write(errorMsg.toJson());
								output.newLine();
								output.flush();
							}

							log.info("[LocalPeer] Directory doesn't exist, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());

							break;
						}

						fileSystemManager.deleteDirectory(pathName);
						String messageString = "Directory was deleted";
						Document directoryDeleteMessage = Protocol.createDirectoryDeleteResponse(pathName, messageString, true);

						synchronized (output) {
							output.write(directoryDeleteMessage.toJson());
							output.newLine();
							output.flush();
						}

						break;
					}

					case"DIRECTORY_DELETE_RESPONSE": {
						log.info("[LocalPeer] A directory delete response was received from " + clientHostPort.toString());
						break;
					}

				}

			}
		} catch (IOException e) {
			log.info("[LocalPeer] Unable to communicate with " + clientHostPort.toString() + ", disconnected!");
		} catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } finally {
			close();
		}
	}
}