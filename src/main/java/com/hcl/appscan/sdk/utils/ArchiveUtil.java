/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import com.hcl.appscan.sdk.Messages;

public class ArchiveUtil {

	private static final double TOO_BIG = 4e9; // 4GB
	private static final int BUFFER_SIZE = 4096;
	
	public static int MAX_PATH_LENGTH = 4096;

    static {
        if (SystemUtil.isWindows()) {
        	MAX_PATH_LENGTH = 256;
        } else if (SystemUtil.isMac()) {
        	MAX_PATH_LENGTH = 1024;
        } else {
        	MAX_PATH_LENGTH = 4096;
        }
    }
	
	/**
	 * Unzip an archive.
	 * 
	 * @param source An input file.
	 * @param destDir The destination directory to unzip to.
	 * @throws IOException If an error occurs during the unzip operation.
	 */
	public static void unzip(File source, File destDir) throws IOException {
		
		FileInputStream input = new FileInputStream(source);
		ZipInputStream zip = new ZipInputStream(new BufferedInputStream(input));
		destDir.mkdirs();
		
		ZipEntry entry = null;
		long bytesWritten = 0;
		
		try {
			while ((entry = zip.getNextEntry()) != null) {
				
				String path = entry.getName();
				File newFile = new File(destDir, path);
				
				if (entry.isDirectory()) {
					newFile.mkdirs();
				}
				else {
					File parent = newFile.getParentFile();
					parent.mkdirs();
					if (parent.isDirectory())
						bytesWritten += write(zip, newFile);
				}
				
				if (bytesWritten >= TOO_BIG)
					throw new IOException(Messages.getMessage("err.too.big")); //$NON-NLS-1$
				
				//Set 755 permissions
				newFile.setExecutable(true, false);
				newFile.setReadable(true, false);
				newFile.setWritable(true);
			}
		}
		finally {
			if(zip != null)
				zip.close();
		}
	}
	
	/**
	 * Read from the input stream and write to the new file.
	 * The caller is responsible for closing the input stream when all reads from it are done. 
	 * 
	 * @param input The input stream.
	 * @param file The output file.
	 * @return The number of bytes written.
	 * @throws IOException if an error occurs during the write.
	 */
	private static long write(InputStream input, File file) throws IOException {
		
		BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream(file));
		
		long bytesWritten = 0;
		int len = 0;
		byte[] buffer = new byte[BUFFER_SIZE];
		
		try {
			while ((len = input.read(buffer)) != -1) {
				output.write(buffer, 0, len);
				bytesWritten += len;
			}
			return bytesWritten;
		}
		finally {
			if(output != null)
				output.close();
		}
	}

    public void zipFolder(String sourceFile, String zipName) throws IOException {
        File fileToZip = new File(sourceFile);
        FileOutputStream fos = new FileOutputStream(System.getProperty("java.io.tmpdir")+File.separator+zipName+".zip");
        ZipOutputStream zipOut = new ZipOutputStream(fos);

        zipFile(fileToZip, fileToZip.getName(), zipOut);
        zipOut.close();
        fos.close();
    }

    private static void zipFile(File fileToZip, String fileName, ZipOutputStream zipOut) throws IOException {
        if (fileToZip.isHidden()) {
            return;
        }
        if (fileToZip.isDirectory()) {
            File[] children = fileToZip.listFiles();
            for (File childFile : children) {
                zipFile(childFile, fileName + "/" + childFile.getName(), zipOut);
            }
            return;
        }
        FileInputStream fis = new FileInputStream(fileToZip);
        ZipEntry zipEntry = new ZipEntry(fileName);
        zipOut.putNextEntry(zipEntry);
        byte[] bytes = new byte[1024];
        int length;
        while ((length = fis.read(bytes)) >= 0) {
            zipOut.write(bytes, 0, length);
        }
        fis.close();
    }
}
