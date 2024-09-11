/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners;

import java.io.Serializable;
import java.util.Map;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.logging.DefaultProgress;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.results.CloudResultsProvider;
import com.hcl.appscan.sdk.results.IResultsProvider;
import com.hcl.appscan.sdk.results.NonCompliantIssuesResultProvider;
import com.hcl.appscan.sdk.scan.IScan;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.utils.SystemUtil;

public abstract class ASoCScan implements IScan, ScanConstants, Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private String m_target;
	private String m_scanId;
        private String m_executionId;
        private Boolean m_rescan;
	private IProgress m_progress;
	private IScanServiceProvider m_serviceProvider;
	private Map<String, String> m_properties;
	
	public ASoCScan(Map<String, String> properties, IScanServiceProvider provider) {
		this(properties, new DefaultProgress(), provider);
	}
	
	public ASoCScan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
		m_target = properties.remove(CoreConstants.TARGET);
		m_properties = properties;
		if(!m_properties.containsKey(CoreConstants.SCAN_NAME))
			m_properties.put(CoreConstants.SCAN_NAME, getType() + SystemUtil.getTimeStamp());
		m_progress = progress;
		m_serviceProvider = provider;
	}

	@Override
	public String getScanId() {
		return m_scanId;
	}
        
        public String getExecutionId() {
		return m_executionId;
	}
        
        public Boolean isRescan() {
		return m_properties.containsKey(CoreConstants.SCAN_ID);
	}

	@Override
	public String getName() {
		return m_properties.get(CoreConstants.SCAN_NAME);
	}
	
	@Override
	public IResultsProvider getResultsProvider() {
		CloudResultsProvider provider = new CloudResultsProvider(m_scanId, getType(), m_serviceProvider, m_progress);
		provider.setReportFormat(getReportFormat());
		return provider;
	}

	@Override
	public IResultsProvider getResultsProvider(boolean nonCompliantIssues) {
		if(nonCompliantIssues) {
			IResultsProvider provider = new NonCompliantIssuesResultProvider(m_scanId, m_executionId, getType(), m_serviceProvider, m_progress);
			provider.setReportFormat(getReportFormat());
			return provider;
		}
		else {
			return getResultsProvider();
		}
	}
	
	protected void setScanId(String id) {
		m_scanId = id;
	}
        
        protected void setExecutionId(String id){
		m_executionId = id;
	}
        
        public void setRescan(Boolean rescan){
                m_rescan = rescan;
	}
	
	protected String getAppId() {
		return m_properties.get(CoreConstants.APP_ID);
	}
	
	protected String getTarget() {
		return m_target;
	}
	
	public void setTarget(String target) {
		m_target = target;
	}
	
	public IProgress getProgress() {
		return m_progress;
	}
	
	public IScanServiceProvider getServiceProvider() {
		return m_serviceProvider;
	}
	
	protected Map<String, String> getProperties() {
		if(!m_properties.containsKey(CoreConstants.LOCALE))
			m_properties.put(CoreConstants.LOCALE, SystemUtil.getLocale());
		if(!m_properties.containsKey(CoreConstants.EMAIL_NOTIFICATION) ||
				!Boolean.parseBoolean(m_properties.get(CoreConstants.EMAIL_NOTIFICATION)))
			m_properties.put(CoreConstants.EMAIL_NOTIFICATION, Boolean.toString(false));
		return m_properties;
	}
	
        protected void submitRescan() {
        	    setExecutionId(getServiceProvider().rescan(getScanId(),getProperties()));
    	}
         
	public abstract String getReportFormat();
}