package com.hcl.appscan.sdk.scanners.sast.targets;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * A generic target for a given file or directory.
 */
public class GenericTarget extends DefaultTarget {

	private File m_targetFile;
	private Map m_properties;
	
	public GenericTarget(String target) {
		m_targetFile = new File(target);
		m_properties = new HashMap<String, String>();
	}
	
	@Override
	public File getTargetFile() {
		return m_targetFile;
	}

	@Override
	public Map<String, String> getProperties() {
		return m_properties;
	}
}
