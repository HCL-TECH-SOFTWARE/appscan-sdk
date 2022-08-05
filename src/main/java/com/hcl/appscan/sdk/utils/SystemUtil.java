/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.utils;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.scanners.sast.xml.IModelXMLConstants;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class SystemUtil {

	private static final String TIMESTAMP_FORMAT = "yyyy-MM-dd_HH-mm-ss"; //$NON-NLS-1$
			
	/** Gets a timestamp using the default format.
	 * @return The current timestamp.
	 */
	public static String getTimeStamp() {
		return getTimeStamp(TIMESTAMP_FORMAT);
	}
	
	/**
	 * Gets a timestamp using the given format.
	 * @param format The format of the timestamp.
	 * @return The current timestamp.
	 */
    public static String getTimeStamp(String format) {
		Date date = new Date();
		SimpleDateFormat sdf;
		
		try {
			sdf = new SimpleDateFormat(format);
		} catch(NullPointerException | IllegalArgumentException e) {
			sdf = new SimpleDateFormat(TIMESTAMP_FORMAT);
		}
		return sdf.format(date);
    }
    
	/**
	 * Adds all properties specified in APPSCAN_OPTS to the system properties.
	 */
	public static void setSystemProperties() {
		String opts = System.getenv("APPSCAN_OPTS"); //$NON-NLS-1$
		if(opts == null || opts.isEmpty())
			return;
		
		String[] properties = opts.split(" "); //$NON-NLS-1$
		for(String property : properties) {
			if(property == null || property.trim().length() == 0)
				continue;
			if(property.startsWith("-D")) //$NON-NLS-1$
				property = property.substring(2);
			String[] prop = property.split("="); //$NON-NLS-1$
			if(prop.length == 2)
				System.setProperty(prop[0], prop[1]);
			else
				System.setProperty(property, ""); //$NON-NLS-1$
		}
	}

	/**
	 * Gets the operating system.
	 * 
	 * @return A string representing the OS name. One of "win", "mac", or "linux".
	 */
	public static String getOS() {
		String os = System.getProperty("os.name"); //$NON-NLS-1$
		
		if(os.startsWith("Windows")) //$NON-NLS-1$
			os = "win"; //$NON-NLS-1$
		else if(os.startsWith("Mac")) //$NON-NLS-1$
			os = "mac"; //$NON-NLS-1$
		else
			os = "linux"; //$NON-NLS-1$

		return os;
	}
	
	/**
	 * Determine if running on Windows.
	 * 
	 * @return True if running on Windows.
	 */
	public static boolean isWindows() {
		return System.getProperty("os.name").startsWith("Windows"); //$NON-NLS-1$ //$NON-NLS-2$
	}
	
	/**
	 * Determine if running on Mac OS.
	 * 
	 * @return True if running on Mac OS.
	 */
	public static boolean isMac() {
		return System.getProperty("os.name").startsWith("Mac"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Gets the server url.
	 * 
	 * @return The server url.
	 */
	public static String getDefaultServer() {
		return ServerUtil.getServerUrl();
	}

	/**
	 * Gets the server url.
	 * @param key The key to use for determining the server region.
	 * 
	 * @return The server url.
	 */
	public static String getServer(String key) {
		// If the key is prefixed with a region, it will be separated with an '_' character.
		if( key.contains("_"))
			key = key.substring(0, key.indexOf("_")); //$NON-NLS-1$
		return ServerUtil.getServerUrl(key);
	}
	
	/**
	 * Get the system locale.
	 * 
	 * @return A string representation of the system's locale.
	 */
	public static String getLocale() {
		return Locale.getDefault().toString().replace('_', '-'); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Check if source code only enabled.
	 *
	 * @return True if source code only enabled.
	 */
	public static boolean isSourceCodeOnly() {
		return System.getProperty(CoreConstants.SOURCE_CODE_ONLY) != null;
	}
	
	/**
	 * Get the IRX cache location from IRX_MINOR_CACHE_HOME flag
	 *
	 * @return A string representation of the user-specified irx cache location
	 */
	public static String getIrxMinorCacheHome() {
		String irx_cache_path = "";
		if (System.getProperty(IModelXMLConstants.A_IRX_MINOR_CACHE_HOME.toUpperCase()) != null)
			irx_cache_path = System.getProperty(IModelXMLConstants.A_IRX_MINOR_CACHE_HOME.toUpperCase());
		return irx_cache_path;
	}
}
