package unimelb.bitbox.util;

import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

public interface FileSystemObserver {
	void processFileSystemEvent(FileSystemEvent fileSystemEvent);
}
