/*************************************************************************
* IBM and/or HCL Confidential
* AppScan Static Analyzer
* (c) Copyright IBM Corp. 2013, 2017 All Rights Reserved.
* (c) Copyright HCL Technologies, Ltd. 2023, 2026 All Rights Reserved.
*
* The source code for this program is not published or otherwise
* divested of its trade secrets, irrespective of what has been
* deposited with the U.S. Copyright Office.
*/

package com.hcl.appscan.sdk.utils;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Enumeration;

import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.io.IOUtils;

import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.utils.SystemUtil;

/**
 * Utility to unzip Zip archives that contain symlinks.
 */
public class ArchiveUtilSymlinks {

	private static Boolean processEntry(ZipFile zipFile, ZipArchiveEntry entry, File dest, boolean setPermissions) throws IOException {
		try {
			final File f = new File(dest, entry.getName());

			if (entry.isDirectory()) {
				if (!f.isDirectory() && !f.mkdirs()) {
					return false;
				}
			}
			else {
				final File parent = f.getParentFile();
				if (!parent.isDirectory() && !parent.mkdirs()) {
					return false;
				}

				if (entry.isUnixSymlink()) {
					// Skip if Windows (or make copy or abort ?)
					if (! SystemUtil.isWindows()) {
						final String target = zipFile.getUnixSymlink(entry);
						if (target == null) {
							return false;
						}
						final Path targetPath = Paths.get(target);
						Files.createSymbolicLink(f.toPath(), targetPath);
					}
				}
				else {
					try ( InputStream content = zipFile.getInputStream(entry);
						OutputStream o = Files.newOutputStream(f.toPath()) )
					{
						IOUtils.copyLarge(content, o);
					}
				}
			}

			if (setPermissions) {
				//Set rwx permissions
				f.setExecutable(true, false);
				f.setReadable(true, false);
				f.setWritable(true);
			}

		} catch(IOException e) {
			throw new IOException(e);
		}
		return true;
	}

	/**
	 * Unzip an archive, immediately halting upon error.
	 * 
	 * @param source The source archive.
	 * @param dest The destination directory to unzip to.
	 * @throws IOException If an error occurs during the unzip operation.
	 */
	public void unzip(File source, File dest) throws IOException {

		// See https://commons.apache.org/proper/commons-compress/examples.html
		// and https://issues.apache.org/jira/browse/COMPRESS-689 for why this
		// handling must use Apache's ZipFile rather than ArchiveInputStream/ZipArchiveInputStream
		try ( ZipFile zipFile = ZipFile.builder().setFile(source).get() )
		{
			Enumeration<ZipArchiveEntry> entries = zipFile.getEntries();
			Collections.list(entries).forEach(entry -> {
				try {
					if (! processEntry(zipFile, entry, dest, true)) {
						final File f = new File(dest, entry.getName());
						throw new IOException(Messages.getMessage("err.invalid.path", f.getPath())); //$NON-NLS-1$
					}
				}
				catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			});
		}
		catch (IOException | UncheckedIOException e) {
			throw new IOException(e);
		}
	}
}
