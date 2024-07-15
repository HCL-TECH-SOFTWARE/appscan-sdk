/**
 * © Copyright HCL Technologies Ltd. 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast;

import java.util.Map;

import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.DefaultProgress;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.results.CloudCombinedResultsProvider;
import com.hcl.appscan.sdk.results.IResultsProvider;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.sca.SCAScan;

public class SAST_SCA_Scan extends SASTScan {

	private static final long serialVersionUID = 1L;
	
	private String m_sastScanId;
	private String m_scaScanId;
	private SCAScan m_scaScan;
	
	public SAST_SCA_Scan(Map<String, String> properties, IScanServiceProvider provider) {
		super(properties, new DefaultProgress(), provider);
		m_scaScan = new SCAScan(properties, new DefaultProgress(), provider);
		m_scaScan.setTarget(getTarget()); //Need to explicitly set the target since it's removed when the SAST scan was created.
	}
	
	public SAST_SCA_Scan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
		super(properties, progress, provider);
		m_scaScan = new SCAScan(properties, progress, provider);
		m_scaScan.setTarget(getTarget()); //Need to explicitly set the target since it's removed when the SAST scan was created.
	}

	@Override
	public void run() throws ScannerException, InvalidTargetException {
		super.run();
		if(getProperties().containsKey(PREPARE_ONLY)) {
			//Avoid generating 2 .irx files.
			return;
		}
		else {
			m_sastScanId = getScanId();
			m_scaScan.run();
			m_scaScanId = m_scaScan.getScanId();
		}
	}
	
	@Override
	public IResultsProvider getResultsProvider() {
		CloudCombinedResultsProvider provider = new CloudCombinedResultsProvider(getResultsProvider(), m_scaScan.getResultsProvider());
		provider.setReportFormat(getReportFormat());
		return provider;
	}
	
	public String getSastScanId() {
		return m_sastScanId;
	}
	
	public String getScaScanId() {
		return m_scaScanId;
	}
}
