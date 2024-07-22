/**
 * © Copyright HCL Technologies Ltd. 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.results;

import java.io.File;
import java.io.Serializable;
import java.util.Collection;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.logging.IProgress;

public class CloudCombinedResultsProvider implements IResultsProvider, Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private IResultsProvider m_resultsProvider1;
	private IResultsProvider m_resultsProvider2;
	private String m_reportFormat = DEFAULT_REPORT_FORMAT;
	
	public CloudCombinedResultsProvider(IResultsProvider resultsProvider1, IResultsProvider resultsProvider2) {
		m_resultsProvider1 = resultsProvider1;
		m_resultsProvider2 = resultsProvider2;
	}
	
	@Override
	public boolean hasResults() {
		return m_resultsProvider1.hasResults() || m_resultsProvider2.hasResults();
	}

	@Override
	public String getStatus() {
		String combinedStatus = CoreConstants.RUNNING;
		String status1 = m_resultsProvider1.getStatus();
		String status2 = m_resultsProvider2.getStatus();
		
		if(status1.equalsIgnoreCase(CoreConstants.FAILED) || status2.equalsIgnoreCase(CoreConstants.FAILED)) {
			combinedStatus = CoreConstants.FAILED;
		}
		else if(status1.equalsIgnoreCase(CoreConstants.READY) && status2.equalsIgnoreCase(CoreConstants.READY)) {
			combinedStatus = CoreConstants.READY;
		}
		
		return combinedStatus;
	}

	@Override
	public Collection<?> getFindings() {
		return null;
	}

	@Override
	public int getFindingsCount() {
		return m_resultsProvider1.getFindingsCount() + m_resultsProvider2.getFindingsCount();
	}

	@Override
	public int getCriticalCount() {
		return m_resultsProvider1.getCriticalCount() + m_resultsProvider2.getCriticalCount();
	}

	@Override
	public int getHighCount() {
		return m_resultsProvider1.getHighCount() + m_resultsProvider2.getHighCount();
	}

	@Override
	public int getMediumCount() {
		return m_resultsProvider1.getMediumCount() + m_resultsProvider2.getMediumCount();
	}

	@Override
	public int getLowCount() {
		return m_resultsProvider1.getLowCount() + m_resultsProvider2.getLowCount();
	}

	@Override
	public int getInfoCount() {
		return m_resultsProvider1.getInfoCount() + m_resultsProvider2.getInfoCount();
	}

	@Override
	public String getType() {
		return m_resultsProvider1.getType() + "_" + m_resultsProvider2.getType();
	}

	@Override
	public void getResultsFile(File destination, String format) {
		//Append the technology type to the end of the file name.
		String name = destination.getName();
		File directory = destination.getParentFile();
		m_resultsProvider1.getResultsFile(new File(directory, name), format);
		m_resultsProvider2.getResultsFile(new File(directory, name), format);
	}

	@Override
	public String getResultsFormat() {
		return m_reportFormat;
	}

	@Override
	public String getMessage() {
        if(m_resultsProvider1.getMessage() != null  && m_resultsProvider2.getMessage() != null) {
            return m_resultsProvider1.getType() + ": " + m_resultsProvider1.getMessage() + "\n" +
                    m_resultsProvider2.getType() + ": " + m_resultsProvider2.getMessage();
        }
        return null;
	}

	@Override
	public void setReportFormat(String format) {
		m_reportFormat = format;
		m_resultsProvider1.setReportFormat(format);
		m_resultsProvider2.setReportFormat(format);
	}

	@Override
	public void setProgress(IProgress progress) {
		m_resultsProvider1.setProgress(progress);
		m_resultsProvider2.setProgress(progress);
	}
}
