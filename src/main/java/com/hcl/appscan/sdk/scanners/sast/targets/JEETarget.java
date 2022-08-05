/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast.targets;

import java.util.Map;

import com.hcl.appscan.sdk.scanners.sast.xml.IModelXMLConstants;

public abstract class JEETarget extends JavaTarget implements IJEETarget {

	@Override
	public Map<String, String> getProperties() {
		Map<String, String> buildInfos = super.getProperties();
		buildInfos.put(IModelXMLConstants.A_JSP_COMPILER, getJSPCompiler());
		return buildInfos;
	}
}
