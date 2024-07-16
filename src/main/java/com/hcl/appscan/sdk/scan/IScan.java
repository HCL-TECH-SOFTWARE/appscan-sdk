/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scan;

import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.results.IResultsProvider;

public interface IScan {

	/**
	 * Runs a scan.
	 * 
	 * @throws ScannerException if a fatal error occurs in the scan.
	 * @throws InvalidTargetException if the target is invalid.
	 */
	public void run() throws ScannerException, InvalidTargetException;
	
	/**
	 * Gets the id of the scan.
	 * 
	 * @return The scan Id.
	 */
	public String getScanId();
	
	/**
	 * The type of scan.
	 * 
	 * @return A String identifying the type of scan.
	 */
	public String getType();
	
	/**
	 * Gets a provider for accessing the scan results.
	 * 
	 * @return The {@link IResultsProvider}.
	 */
	public IResultsProvider getResultsProvider();
    
	/**
	 * Gets a provider for accessing the scan results.
	 * 
	 * @param nonCompliantIssues Only include noncompliant issues in the results.
	 * @return The {@link IResultsProvider}.
	 */
	public IResultsProvider getResultsProvider(boolean nonCompliantIssues);
	
	/**
	 * Gets the name of the scan.
	 * 
	 * @return The name of the scan.
	 */
	public String getName();
        
        /**
	 * Gets the provider of scanning services. 
	 * 
	 * @return The {@link IScanServiceProvider}.
	 */
        public IScanServiceProvider getServiceProvider(); 
        
        public String getReportFormat();
}
