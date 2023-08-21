package com.hcl.appscan.sdk.scanners.sca;

import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ASoCScan;
import com.hcl.appscan.sdk.scanners.sast.SAClient;
import com.hcl.appscan.sdk.scanners.sast.SASTConstants;

import java.io.File;
import java.io.IOException;
import java.net.Proxy;
import java.util.Map;

public class SCAScan extends ASoCScan implements SASTConstants {
    private static final long serialVersionUID = 1L;
    private static final String REPORT_FORMAT = "html"; //$NON-NLS-1$
    private File m_irx;

    public SCAScan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
        super(properties, progress, provider);
    }

    @Override
    public void run() throws ScannerException, InvalidTargetException {
        String target = getTarget();

        if(target == null || !(new File(target).exists()))
            throw new InvalidTargetException(Messages.getMessage(TARGET_INVALID, target));

        try {
            generateIR();
            analyzeIR();
        } catch(IOException e) {
            throw new ScannerException(Messages.getMessage(SCAN_FAILED, e.getLocalizedMessage()));
        }
    }

    @Override
    public String getType() {
        return "Software Composition Analysis";
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
        if(targetFile.getName().endsWith(".irx") && targetFile.isFile()) {
            m_irx = targetFile;
            return;
        }

        //Get the target directory
        String targetDir = targetFile.isDirectory() ? targetFile.getAbsolutePath() : targetFile.getParent();

        //Create and run the process
        Proxy proxy = getServiceProvider() == null ? Proxy.NO_PROXY : getServiceProvider().getAuthenticationProvider().getProxy();
        new SAClient(getProgress(), proxy).run(targetDir, getProperties());
        String irxDir = getProperties().containsKey(SAVE_LOCATION) ? getProperties().get(SAVE_LOCATION) : targetDir;
        m_irx = new File(irxDir, getName() + IRX_EXTENSION);
        if(!m_irx.isFile())
            throw new ScannerException(Messages.getMessage(ERROR_GENERATING_IRX, getScanLogs().getAbsolutePath()));
    }

    private void analyzeIR() throws IOException, ScannerException {
        if(getProperties().containsKey(PREPARE_ONLY))
            return;

        String fileId = getServiceProvider().submitFile(m_irx);
        if(fileId == null)
            throw new ScannerException(Messages.getMessage(ERROR_FILE_UPLOAD, m_irx.getName()));

        Map<String, String> params = getProperties();
        params.put(ARSA_FILE_ID, fileId);

        setScanId(getServiceProvider().createAndExecuteScan("Software Composition Analysis", params));
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
