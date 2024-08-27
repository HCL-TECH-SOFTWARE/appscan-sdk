/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.transform.TransformerException;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.AppScanException;
import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.IScanManager;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scan.ITarget;
import com.hcl.appscan.sdk.scanners.sast.targets.ISASTTarget;
import com.hcl.appscan.sdk.scanners.sast.xml.ModelWriter;
import com.hcl.appscan.sdk.scanners.sast.xml.XmlWriter;
import com.hcl.appscan.sdk.scanners.sca.SCAScan;
import com.hcl.appscan.sdk.utils.ServiceUtil;
import com.hcl.appscan.sdk.utils.SystemUtil;

public class SASTScanManager implements IScanManager{
	
	private List<ISASTTarget> m_targets;
	private SASTScan m_scan;
	private String m_workingDirectory;
	private boolean m_isThirdPartyScanningEnabled = false;
	private boolean m_isOpenSourceOnlyEnabled = false;
	private boolean m_isSourceCodeOnlyEnabled = false;
	private boolean m_isStaticAnalysisOnlyEnabled = false;
	private boolean m_isSecretsScanningDisabled = false;
	private boolean m_isSecretsScanningOnlyEnabled = false;

	public SASTScanManager(String workingDir) {
		m_workingDirectory = workingDir;
		m_targets = new ArrayList<>();
	}

	@Override
	public void prepare(IProgress progress, Map<String, String> properties) throws AppScanException {
		createConfig();
		properties.put(CoreConstants.TARGET, m_workingDirectory);
		properties.put(SASTConstants.PREPARE_ONLY, Boolean.toString(true));
		if(!properties.containsKey(CoreConstants.SCAN_NAME))
			properties.put(CoreConstants.SCAN_NAME, getDefaultScanName());
		run(progress, properties, null);
	}

	@Override
	public void analyze(IProgress progress, Map<String, String> properties, IScanServiceProvider provider) throws AppScanException {
		if(m_scan == null || m_scan.getIrx() == null) {
			createConfig();
			properties.put(CoreConstants.TARGET, m_workingDirectory);
		}
		else
			properties.put(CoreConstants.TARGET, m_scan.getIrx().getAbsolutePath());
		
		if(!properties.containsKey(CoreConstants.SCAN_NAME))
			properties.put(CoreConstants.SCAN_NAME, getDefaultScanName());
		
		run(progress, properties, provider);
	}
	
	@Override
	public void addScanTarget(ITarget target) {
		if(target instanceof ISASTTarget)
			m_targets.add((ISASTTarget)target);
	}

	@Override
	public void getScanResults(File destination, String format) throws AppScanException {
		if(m_scan != null && m_scan.getResultsProvider() != null)
			m_scan.getResultsProvider().getResultsFile(destination, format);
		else
			throw new AppScanException(Messages.getMessage("message.results.unavailable")); //$NON-NLS-1$
	}

	/**
	 * Gets the scan id.
	 * @return The scan id as a String, if one has been created. Otherwise null.
	 */
	public String getScanId() {
		return m_scan == null ? null : m_scan.getScanId();
	}
	
	private void run(IProgress progress,Map<String, String> properties, IScanServiceProvider provider) throws AppScanException {
		try {
			createScan(properties, progress, provider);
			m_scan.run();
		} catch (InvalidTargetException | ScannerException e) {
			throw new AppScanException(e.getLocalizedMessage());
		}
	}
	
	/**
	 * Enables the scanning of third party libraries that are excluded by default.
	 * @param isThirdPartyScanningEnabled - True to enable the scanning of known 3rd party libraries that are excluded by default.
	 */
	public void setIsThirdPartyScanningEnabled(boolean isThirdPartyScanningEnabled) {
		m_isThirdPartyScanningEnabled = isThirdPartyScanningEnabled;
	}

	/**
	 * Disables scanning for secrets.
	 * @param isSecretsScanningDisabled - True to skip scanning for secrets vulnerabilities.
	 */
	public void setIsSecretsScanningDisabled(boolean isSecretsScanningDisabled) {
		System.out.println("inside sdk, setting to " + String.valueOf(isSecretsScanningDisabled));
		m_isSecretsScanningDisabled = isSecretsScanningDisabled;
	}

	/**
	 * Only scan for secrets.
	 * @param isSecretsScanningOnlyEnabled - True to only scan for secrets vulnerabilities.
	 */
	public void setIsSecretsScanningOnlyEnabled(boolean isSecretsScanningOnlyEnabled) {
		m_isSecretsScanningOnlyEnabled = isSecretsScanningOnlyEnabled;
	}

	/**
	 * Only scan for known vulnerabilities in 3rd party libraries. Disables static analysis.
	 * @param isOpenSourceOnlyEnabled - True to scan only for known vulnerabilities in 3rd party libraries.
	 */
	public void setIsOpenSourceOnlyEnabled(boolean isOpenSourceOnlyEnabled) {
		m_isOpenSourceOnlyEnabled = isOpenSourceOnlyEnabled;
	}

	/**
	 * Only scan source code files. Ignore other file types such as .jar, .war, .dll, etc.
	 * @param isSourceCodeOnlyEnabled - True to only scan source code files.
	 */
	public void setIsSourceCodeOnlyEnabled(boolean isSourceCodeOnlyEnabled) {
		m_isSourceCodeOnlyEnabled = isSourceCodeOnlyEnabled;
	}
	
	/**
	 * Only run static analysis. Disables scanning for known vulnerabilities in 3rd party libraries.
	 * @param isStaticAnalysisOnlyEnabled - True to scan only for known vulnerabilities in 3rd party libraries.
	 */
	public void setIsStaticAnalysisOnlyEnabled(boolean isStaticAnalysisOnlyEnabled) {
		m_isStaticAnalysisOnlyEnabled = isStaticAnalysisOnlyEnabled;
	}

	public void createConfig() throws AppScanException {
		createConfig(false);
	}
	
	public void createConfig(boolean useRelativeTargetPaths) throws AppScanException  {
		if(m_targets.isEmpty())
			return;
		try {
			ModelWriter writer = new XmlWriter(useRelativeTargetPaths);
			writer.initWriters(new File(m_workingDirectory));		
			writer.visit(m_targets, m_isThirdPartyScanningEnabled, m_isOpenSourceOnlyEnabled, m_isSourceCodeOnlyEnabled, m_isStaticAnalysisOnlyEnabled, m_isSecretsScanningDisabled, m_isSecretsScanningOnlyEnabled);
			writer.write();
		} catch (IOException | TransformerException  e) {
			throw new AppScanException(e.getLocalizedMessage(), e);
		}
	}
	
	private String getDefaultScanName() {
		return new File(m_workingDirectory).getName() + SystemUtil.getTimeStamp();
	}
	
	private void createScan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
		if(m_isOpenSourceOnlyEnabled ) {
			m_scan = new SCAScan(properties, progress, provider);
		}
		else if(m_isStaticAnalysisOnlyEnabled || (provider != null && !ServiceUtil.hasScaEntitlement(provider.getAuthenticationProvider()))) {
			m_scan = new SASTScan(properties, progress, provider);
		}
		else {
			m_scan = new SAST_SCA_Scan(properties, progress, provider);
		}
	}
}
