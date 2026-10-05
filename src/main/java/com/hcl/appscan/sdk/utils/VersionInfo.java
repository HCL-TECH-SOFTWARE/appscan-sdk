/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2026.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

/**
 * Holds the version.info values.
 */
public class VersionInfo {
	
	public static final String VERSION_FILE = "version.info"; //$NON-NLS-1$
	
	private File m_file;
	
	private String m_version;
	private String m_os;
	private String m_keyID;
	private String m_arch;
	
	public VersionInfo(InputStream is) throws IOException {
		reload(new InputStreamReader(is));
	}
	
	public VersionInfo(String path) {
		m_file = new File(path, VERSION_FILE);
		try {
			reload();
		}
		catch (IOException e) {
			// ignore
		}
	}
	
	private void reload(Reader reader) throws IOException {
		
		BufferedReader br = new BufferedReader(reader);
		
		try {
			m_version =  br.readLine();
			m_os = br.readLine();
			m_keyID = br.readLine();
			m_arch = br.readLine();
		}
		finally {
			if (br != null) {
				try {
					br.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}
	
	/**
	 * Reload values from the version.info file.
	 * 
	 * @throws IOException
	 */
	public void reload() throws IOException {
		if (m_file != null && m_file.isFile())
			reload(new FileReader(m_file));
	}
	
	/**
	 * Get the version value.
	 * 
	 * @return The version value.
	 */
	public String getVersion() {
		return m_version;
	}
	
	/**
	 * Get the OS value.
	 * 
	 * @return The OS value.
	 */
	public String getOS() {
		return m_os;
	}
	
	/**
	 * Get the key ID value.
	 * 
	 * @return The key ID value.
	 */
	public String getKeyID() {
		return m_keyID;
	}
	
	/**
	 * Get the architecture of the current build/package.
	 * 
	 * @return The architecture value.
	 */
	public String getArchitecture() {
		return m_arch;
	}
}
