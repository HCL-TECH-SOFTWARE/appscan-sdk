/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2022. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast.xml;

public interface IModelXMLConstants {

	String APPSCAN_CONFIG			= "appscan-config";			//$NON-NLS-1$
	String DOT_XML					= ".xml";					//$NON-NLS-1$
	
	String E_CONFIGURATION			= "Configuration";			//$NON-NLS-1$
	String E_TARGETS				= "Targets";				//$NON-NLS-1$
	String E_TARGET					= "Target";					//$NON-NLS-1$
	String E_TARGET_SETTINGS		= "TargetSettings";			//$NON-NLS-1$
	String E_CUSTOM_BUILD_INFO		= "CustomBuildInfo";		//$NON-NLS-1$
	String E_INCLUDE				= "Include";				//$NON-NLS-1$
	String E_EXCLUDE				= "Exclude";				//$NON-NLS-1$

	//Configuration Options
	String A_THIRD_PARTY            = "thirdParty";             //$NON-NLS-1$
	String A_OPEN_SOURCE_ONLY       = "openSourceOnly";         //$NON-NLS-1$
	String A_SOURCE_CODE_ONLY		= "sourceCodeOnly";         //$NON-NLS-1$
	String A_STATIC_ANALYSIS_ONLY	= "staticAnalysisOnly";     //$NON-NLS-1$

	//Java
	String A_PATH					= "path";					//$NON-NLS-1$
	String A_SRC_PATH				= "src_path";				//$NON-NLS-1$
	String A_SRC_ROOT				= "src_root";				//$NON-NLS-1$
	String A_JDK_PATH				= "jdk_path";				//$NON-NLS-1$
	String A_JSP_COMPILER			= "jsp_compiler";			//$NON-NLS-1$
	String A_ADDITIONAL_CLASSPATH	= "additional_classpath";	//$NON-NLS-1$
	String A_OUTPUTS_ONLY			= "outputs-only";			//$NON-NLS-1$
	
	//C++
	String A_COMPILER_OPTS			= "compiler_opts";			//$NON-NLS-1$
	String A_MACROS					= "macros";					//$NON-NLS-1$
	String A_INCLUDE_PATHS			= "include_paths";			//$NON-NLS-1$
	String A_BUILD_CONFIG			= "build_configuration";	//$NON-NLS-1$
	String A_SOURCES			    = "sources";			    //$NON-NLS-1$
	String A_VS_VERSION			    = "vs_version";			    //$NON-NLS-1$
	String A_INTERMEDIATE_OUTPUT_PATH = "intermediate_output_path"; //$NON-NLS-1$
	String A_PLATFORM_ARCH			= "platform_architecture";	//$NON-NLS-1$
	
	//.NET
	String A_REFERENCES 			= "references";				//$NON-NLS-1$
	String A_FRAMEWORK 				= "framework_version";		//$NON-NLS-1$
}
