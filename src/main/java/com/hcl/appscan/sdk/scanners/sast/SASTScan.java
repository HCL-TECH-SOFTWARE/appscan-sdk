/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast;

import java.io.File;
import java.io.IOException;
import java.net.Proxy;
import java.util.Map;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.DefaultProgress;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ASoCScan;
import com.hcl.appscan.sdk.utils.ArchiveUtil;
import com.hcl.appscan.sdk.utils.FileUtil;

/**
 * A class for running static scans. For greater control over what gets scanned a {@link SASTScanManager} should be used.
 */
public class SASTScan extends ASoCScan implements SASTConstants {

	private static final long serialVersionUID = 1L;
	private static final String REPORT_FORMAT = "html"; //$NON-NLS-1$
	
	private File m_irx;
	
	public SASTScan(Map<String, String> properties, IScanServiceProvider provider) {
		super(properties, new DefaultProgress(), provider);
	}
	
	public SASTScan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
		super(properties, progress, provider);
	}
	
	@Override
	public void run() throws ScannerException, InvalidTargetException {
		String target = getTarget();
		
		if(target == null || !(new File(target).exists()))
			throw new InvalidTargetException(Messages.getMessage(TARGET_INVALID, target));

        try {
            if(getProperties().containsKey(CoreConstants.UPLOAD_DIRECT)){
                generateZip();
            } else {
                generateIR();
            }
            analyzeIR();
        } catch(IOException e) {
            throw new ScannerException(Messages.getMessage(SCAN_FAILED, e.getLocalizedMessage()));
        }
	}

	@Override
	public String getType() {
		return SAST;
	}
	
	@Override
	public String getReportFormat() {
		return REPORT_FORMAT;
	}

	public File getIrx() {
		return m_irx;
	}
	
	private void generateIR() throws IOException, ScannerException {
		File targetFile = new File(getTarget());

		//If we were given an irx file, don't generate a new one
		if(targetFile.getName().endsWith(IRX_EXTENSION) && targetFile.isFile()) {
			m_irx = targetFile;
			return;
		}

		//Get the target directory
		String targetDir = targetFile.isDirectory() ? targetFile.getAbsolutePath() : targetFile.getParent();

		//Create and run the process
		Proxy proxy = getServiceProvider() == null ? Proxy.NO_PROXY : getServiceProvider().getAuthenticationProvider().getProxy();		
		new SAClient(getProgress(), proxy).run(targetDir, getProperties());
		String irxDir = getProperties().containsKey(SAVE_LOCATION) ? getProperties().get(SAVE_LOCATION) : targetDir;
		m_irx = new File(irxDir, FileUtil.getValidFilename(getName()) + IRX_EXTENSION);
		if(!m_irx.isFile())
			throw new ScannerException(Messages.getMessage(ERROR_GENERATING_IRX, getScanLogs().getAbsolutePath()));
	}

    private void generateZip() throws IOException,ScannerException {
        File targetFile = new File(getTarget());
        if(targetFile.isFile()){
            m_irx = targetFile;
        } else if (targetFile.isDirectory()) {
            String validatedZipName = FileUtil.getValidFilename(getName());
            String zipLocation = System.getProperty("java.io.tmpdir")+File.separator+validatedZipName+ZIP_EXTENSION;
            ArchiveUtil.zipFileOrFolder(targetFile, new File(zipLocation));
            m_irx = new File(zipLocation);
        }
        if(!m_irx.isFile())
            throw new ScannerException(Messages.getMessage(ERROR_GENERATING_ZIP, getScanLogs().getAbsolutePath()));
    }
	
	private void analyzeIR() throws IOException, ScannerException {
		if(getProperties().containsKey(PREPARE_ONLY))
			return;

		String fileId = getServiceProvider().submitFile(m_irx);
		if(fileId == null)
			throw new ScannerException(Messages.getMessage(ERROR_FILE_UPLOAD, m_irx.getName()));		
				
		Map<String, String> params = getProperties();
		params.put(ARSA_FILE_ID, fileId);
		
		setScanId(getServiceProvider().createAndExecuteScan(STATIC_ANALYZER, params));
		if(getScanId() == null)
			throw new ScannerException(Messages.getMessage(ERROR_SUBMITTING_IRX));
	}
	
	private File getScanLogs() {
		if(m_irx == null) {
			return new File("logs"); //$NON-NLS-1$
		}
		String logsFile = m_irx.getName();
		logsFile = logsFile.substring(0, logsFile.lastIndexOf(".")); //$NON-NLS-1$
		logsFile += "_logs.zip"; //$NON-NLS-1$
		return new File(m_irx.getParentFile(), logsFile);
	}
}
