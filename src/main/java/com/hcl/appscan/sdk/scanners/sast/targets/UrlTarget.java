package com.hcl.appscan.sdk.scanners.sast.targets;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * A target that is a url.
 */
public class UrlTarget extends DefaultTarget {

	private String m_targetFile;
	private Map<String, String> m_properties;
	
	public UrlTarget(String target) {
		m_targetFile = target;
		m_properties = new HashMap<String, String>();
	}
	
	@Override
	public File getTargetFile() {
		return null;
	}
	
	@Override
	public String getTarget() {
		return m_targetFile;
	}

	@Override
	public Map<String, String> getProperties() {
		return m_properties;
	}
}
