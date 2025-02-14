/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024, 2025.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.results;

import java.io.File;
import java.util.Collection;

import com.hcl.appscan.sdk.logging.IProgress;

/**
 * Provides access to the results of a security scan.
 */
public interface IResultsProvider {

	public static String DEFAULT_REPORT_FORMAT = "html"; //$NON-NLS-1$
	
	/**
	 * Answers whether or not this provider contains any results.
	 * @return True if the provider has results.
	 */
	public boolean hasResults();
	
	/**
	 * Gets the status of the results.
	 * @return The status of the results.
	 */
	public String getStatus();
	
	/**
	 * Gets all findings in the result.
	 * @return A collection of findings.
	 */
	public Collection<?> getFindings();
	
	/**
	 * The number of findings in the result.
	 * @return The total number of findings.
	 */
	public int getFindingsCount();

        /**
         * The number of critical findings in the result.
         * @return The total number of critical findings.
        */
        public int getCriticalCount();
	
	/**
	 * The number of high findings in the result.
	 * @return The total number of high findings.
	 */
	public int getHighCount();
	
	/**
	 * The number of medium findings in the result.
	 * @return The total number of medium findings.
	 */
	public int getMediumCount();
	
	/**
	 * The number of low findings in the result.
	 * @return The total number of low findings.
	 */
	public int getLowCount();
	
	/**
	 * The number of info findings in the result.
	 * @return The total number of info findings.
	 */
	public int getInfoCount();
	
	/**
	 * The type of results.  For example, SAST, SCA or DAST.
	 * @return A string identifying the type of results.
	 */
	public String getType();
	
	/**
	 * Gets the results in a file.
	 * @param destination The File to store the results.
	 * @param format The type of file.
	 */
	public void getResultsFile(File destination, String format);
	
	/**
	 * Gets the format of the results.
	 * @return The format of the results file.
	 */
	public String getResultsFormat();

	/**
	 * Gets the Message as populated from the response describing Scan Status.
	 * @return A string Message complementing the Status.
	 */
	public String getMessage();

	/**
	 * Specifies the format to use for reports.
	 * 
	 * @param format The format of the report. 
	 */
	public void setReportFormat(String format);
	
	/**
	 * Sets the IProgress for tracking status.
	 * @param progress The IProgress.
	 */
	public void setProgress(IProgress progress);
}
