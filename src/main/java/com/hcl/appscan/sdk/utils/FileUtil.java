/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.utils;

import java.io.File;
import java.util.regex.Pattern;

public class FileUtil {

	private static String INVALID_CHAR_REGEX = "^[()._ -]+$"; //$NON-NLS-1$
	
	 /**
	 * Return a name with invalid characters removed.
	 * 
	 * @param filename The filename whose invalid characters are to be removed.
	 * @return The filename whose invalid characters are removed.
	 */
	public static String getValidFilename(String filename) {
		StringBuilder builder = new StringBuilder();
		for (int i=0;i<filename.length();i++) {
			char c = filename.charAt(i);
			if (Character.isSpaceChar(c) 
					|| Character.isLetterOrDigit(c) 
					|| Pattern.matches(INVALID_CHAR_REGEX, c + "")) { //$NON-NLS-1$
				builder.append(c);
			}
		}
		return builder.toString();
	}

    public static String getFileExtension(File file) {
        String fileName = file.getName();
        String extension = "";
        int index = fileName.lastIndexOf('.');
        if(index != -1) {
            extension = fileName.substring(index+1);
        }
        return extension;
    }
}
