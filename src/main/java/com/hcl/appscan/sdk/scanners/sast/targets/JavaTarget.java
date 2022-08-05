/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast.targets;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import com.hcl.appscan.sdk.scanners.sast.xml.IModelXMLConstants;
import com.hcl.appscan.sdk.utils.SystemUtil;

public abstract class JavaTarget extends DefaultTarget implements IJavaTarget {

	@Override
	public Map<String, String> getProperties() {
		HashMap<String, String> buildInfos = new HashMap<String, String>();
		String irx_cache_path = SystemUtil.getIrxMinorCacheHome();
		
		if (irx_cache_path != null) {
			File cache_dir = new File(irx_cache_path);
			cache_dir.mkdir();
			buildInfos.put(IModelXMLConstants.A_IRX_MINOR_CACHE_HOME, irx_cache_path);
		}
		
		buildInfos.put(IModelXMLConstants.A_ADDITIONAL_CLASSPATH, getClasspath());
		buildInfos.put(IModelXMLConstants.A_JDK_PATH, getJava());
		return buildInfos;
	}
}
