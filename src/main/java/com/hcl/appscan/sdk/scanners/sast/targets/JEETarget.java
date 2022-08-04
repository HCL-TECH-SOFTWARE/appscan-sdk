/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast.targets;

import java.io.File;
import java.util.Map;

import com.hcl.appscan.sdk.scanners.sast.xml.IModelXMLConstants;
import com.hcl.appscan.sdk.utils.SystemUtil;

public abstract class JEETarget extends JavaTarget implements IJEETarget {

	@Override
	public Map<String, String> getProperties() {
		Map<String, String> buildInfos = super.getProperties();
		String irx_cache_path = SystemUtil.getIrxMinorCacheHome();
		
		if (irx_cache_path != "") {
			File cache_dir = new File(irx_cache_path);
			cache_dir.mkdir();
			buildInfos.put(IModelXMLConstants.A_IRX_MINOR_CACHE_HOME, irx_cache_path);
		}
		
		buildInfos.put(IModelXMLConstants.A_JSP_COMPILER, getJSPCompiler());
		return buildInfos;
	}
}
