package unimelb.bitbox;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import unimelb.bitbox.util.*;
import unimelb.bitbox.util.Document.*;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;
import unimelb.bitbox.util.FileSystemManager.FileDescriptor;

import javax.print.Doc;
import java.io.*;
import java.net.Socket;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
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
				String pathName;
				FileSystemManager.FileDescriptor file;
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
                        break;

                    case "FILE_CREATE_REQUEST":
                        log.info("[LocalPeer] A file create request was received from " + clientHostPort.toString());

                        pathName = JSON.getString("pathName");
                        file = Protocol.createFileDesctiptorFromDocument(fileSystemManager,JSON);

                        if(!fileSystemManager.isSafePathName(pathName)){
                            String errorString = "Path name is unsafe: File create request failed";
                            Document errorMsg = Protocol.createFileCreateResponse(file,pathName,errorString,false);
                            synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

                            log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());
                            break;
                        }

                        if(fileSystemManager.fileNameExists(pathName)){
                            String errorString = "File name has existed: File create request failed";
                            Document errorMsg = Protocol.createFileCreateResponse(file,pathName,errorString,false);
                            synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

                            log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
                            log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
                            log.info(errorMsg.toJson());
                            break;
                        }

						fileSystemManager.createFileLoader(pathName,JSON.getString("md5"),JSON.getLong("length"),JSON.getLong("lastModified"));
						String messageString = "File loader ready";
						Document fileCreateMessage = Protocol.createFileCreateResponse(file, pathName, messageString, true);
						synchronized (output) {
							output.write(fileCreateMessage.toJson());
							output.newLine();
							output.flush();
						}

						log.info("[LocalPeer] Sent FILE_CREATE_RESPONSE to " + clientHostPort.toString());
						log.info(fileCreateMessage.toJson());

						if(fileSystemManager.checkShortcut(pathName))
						{
							log.info("[LocalPeer] have file with same content" );
							break;
						}

						Document fileByteMessage = Protocol.createFileBytesRequest(file,pathName,JSON.getInteger("position"),JSON.getInteger("length"));
						synchronized (output) {output.write(fileByteMessage.toJson()); output.newLine(); output.flush();}
						log.info("[LocalPeer] A file create  request was received from " + clientHostPort.toString());
						log.info("[LocalPeer] Sent FILE_BYTES_REQUEST to " + clientHostPort.toString());
						log.info((fileByteMessage.toJson()));

						break;


					case "FILE_CREATE_RESPONSE":
						log.info("[LocalPeer] A file create response was received from " + clientHostPort.toString());
						break;

					case "FILE_BYTES_REQUEST":

						if (JSON.getLong("length") <= Long.parseLong(Configuration.getConfigurationValue("blockSize")))
						{
                            pathName = JSON.getString("pathName");
                            file = Protocol.createFileDesctiptorFromDocument(fileSystemManager,JSON);
							String encode= new BASE64Encoder().encode(fileSystemManager.readFile(JSON.getString("md5"),JSON.getLong("position"),JSON.getLong("length")));
							fileSystemManager.readFile(JSON.getString("md5"),JSON.getLong("position"),JSON.getLong("length"));
							Document fileBytesMessage = Protocol.createFileBytesResponse(file,pathName,JSON.getInteger("position"),JSON.getInteger("length"),encode,"successful read",true);
							synchronized (output) {output.write(fileBytesMessage.toJson()); output.newLine(); output.flush();}
							log.info("[LocalPeer] A file bytes request was received from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_BYTES_RESPONSE success to " + clientHostPort.toString());
							log.info((fileBytesMessage.toJson()));
						}else
						{
                            pathName = JSON.getString("pathName");
                            file = Protocol.createFileDesctiptorFromDocument(fileSystemManager,JSON);
							Document errorMsg = Protocol.createFileBytesResponse(file,pathName,JSON.getInteger("position"),JSON.getInteger("length"),"","unsuccessful read",false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}
							log.info("[LocalPeer] A unreasonable file bytes request was received from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_BYTES_RESPONSE failed to " + clientHostPort.toString());
							log.info((errorMsg.toJson()));
						}
						break;

					case"FILE_BYTES_RESPONSE":
                        pathName = JSON.getString("pathName");
                        file = Protocol.createFileDesctiptorFromDocument(fileSystemManager,JSON);
						byte[] bytes = new BASE64Decoder().decodeBuffer(JSON.getString("content"));
						ByteBuffer buf = ByteBuffer.wrap(bytes);
						fileSystemManager.writeFile(pathName,buf,JSON.getLong("position"));
						if(!fileSystemManager.checkWriteComplete(pathName))
						{
							fileByteMessage = Protocol.createFileBytesRequest(file,pathName,JSON.getInteger("position"),JSON.getInteger("length"));
							synchronized (output) {output.write(fileByteMessage.toJson()); output.newLine(); output.flush();}
							log.info("[LocalPeer] A file bytes response was received from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_BYTES_REQUEST to " + clientHostPort.toString());
							log.info((fileByteMessage.toJson()));
						}
						break;

					case"FILE_DELETE_REQUEST":
						log.info("[LocalPeer] A file delete request was received from " + clientHostPort.toString());

						pathName = JSON.getString("pathName");
						file = Protocol.createFileDesctiptorFromDocument(fileSystemManager,JSON);
						if(!fileSystemManager.isSafePathName(pathName)){
							String errorString = "Path name is unsafe: File delete request failed";
							Document errorMsg = Protocol.createFileDeleteResponse(file, pathName, errorString, false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						if(fileSystemManager.fileNameExists(pathName)){
							String errorString = "File name has existed: File delete request failed";
							Document errorMsg = Protocol.createFileDeleteResponse(file,pathName,errorString,false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						messageString = "File loader ready";
						Document fileDeleteMessage = Protocol.createFileDeleteResponse(file,pathName,messageString,true);
						synchronized (output) {output.write(fileDeleteMessage.toJson()); output.newLine(); output.flush();}

						log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
						log.info(fileDeleteMessage.toJson());

						break;

					case "FILE_DELETE_RESPONSE":
						log.info("[LocalPeer] A file delete response was received from " + clientHostPort.toString());
						break;

					case"FILE_MODIFY_REQUEST":
						log.info("[LocalPeer] A file modify request was received from " + clientHostPort.toString());

						pathName = JSON.getString("pathName");
						file = Protocol.createFileDesctiptorFromDocument(fileSystemManager,JSON);
						if(!fileSystemManager.isSafePathName(pathName)){
							String errorString = "Path name is unsafe: File modify request failed";
							Document errorMsg = Protocol.createFileModifyResponse(file, pathName, errorString, false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						if(fileSystemManager.fileNameExists(pathName)){
							String errorString = "File name has existed: File modify request failed";
							Document errorMsg = Protocol.createFileModifyResponse(file,pathName,errorString,false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] File name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent FILE_MODIFY_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						messageString = "File loader ready";
						Document fileModifyMessage = Protocol.createFileModifyResponse(file,pathName,messageString,true);
						synchronized (output) {output.write(fileModifyMessage.toJson()); output.newLine(); output.flush();}

						log.info("[LocalPeer] Sent FILE_DELETE_RESPONSE to " + clientHostPort.toString());
						log.info(fileModifyMessage.toJson());
						break;

					case "FILE_MODIFY_RESPONSE":
						log.info("[LocalPeer] A file modify response was received from " + clientHostPort.toString());
						break;

					case"DIRECTORY_CREATE_REQUEST":
						log.info("[LocalPeer] A directory create request was received from " + clientHostPort.toString());
						pathName = JSON.getString("pathName");
						if(!fileSystemManager.isSafePathName(pathName)){
							String errorString = "Path name is unsafe: Directory create request failed";
							Document errorMsg = Protocol.createDirectoryCreateResponse(pathName, errorString, false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						if(fileSystemManager.dirNameExists(pathName)){
							String errorString = "Directory name has existed: Directory create request failed";
							Document errorMsg = Protocol.createDirectoryCreateResponse(pathName,errorString,false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] Directory name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_CREATE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						messageString = "Directory loader ready";
						Document directoryCreateMessage = Protocol.createDirectoryCreateResponse(pathName,messageString,true);
						synchronized (output) {output.write(directoryCreateMessage.toJson()); output.newLine(); output.flush();}

						break;

					case"DIRECTORY_CREATE_RESPONSE":
						log.info("[LocalPeer] A directory create response was received from " + clientHostPort.toString());
						break;

					case"DIRECTORY_DELETE_REQUEST":
						log.info("[LocalPeer] A directory delete request was received from " + clientHostPort.toString());
						pathName = JSON.getString("pathName");
						if(!fileSystemManager.isSafePathName(pathName)){
							String errorString = "Path name is unsafe: Directory delete request failed";
							Document errorMsg = Protocol.createDirectoryDeleteResponse(pathName, errorString, false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] Path name is unsafe, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						if(fileSystemManager.dirNameExists(pathName)){
							String errorString = "Directory name has existed: Directory delete request failed";
							Document errorMsg = Protocol.createDirectoryDeleteResponse(pathName,errorString,false);
							synchronized (output) {output.write(errorMsg.toJson()); output.newLine(); output.flush();}

							log.info("[LocalPeer] Directory name has existed, refused request from " + clientHostPort.toString());
							log.info("[LocalPeer] Sent DIRECTORY_DELETE_RESPONSE to " + clientHostPort.toString());
							log.info(errorMsg.toJson());
							break;
						}

						messageString = "Directory loader ready";
						Document directoryDeleteMessage = Protocol.createDirectoryDeleteResponse(pathName,messageString,true);
						synchronized (output) {output.write(directoryDeleteMessage.toJson()); output.newLine(); output.flush();}
						break;

					case"DIRECTORY_DELETE_RESPONSE":
						log.info("[LocalPeer] A directory delete response was received from " + clientHostPort.toString());
						break;

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