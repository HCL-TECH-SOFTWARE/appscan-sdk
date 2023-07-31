/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2023. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast;


public interface SASTConstants {

	String APPSCAN_INSTALL_DIR			= "APPSCAN_INSTALL_DIR";			//$NON-NLS-1$
	String APPSCAN_IRGEN_CLIENT         = "APPSCAN_IRGEN_CLIENT";			//$NON-NLS-1$
	String APPSCAN_CLIENT_VERSION       = "APPSCAN_CLIENT_VERSION";			//$NON-NLS-1$
	String IRGEN_CLIENT_PLUGIN_VERSION  = "IRGEN_CLIENT_PLUGIN_VERSION";	//$NON-NLS-1$
	String ARSA_FILE_ID					= "ARSAFileId";						//$NON-NLS-1$
	String WIN_SCRIPT					= "appscan.bat";					//$NON-NLS-1$
	String UNIX_SCRIPT					= "appscan.sh";						//$NON-NLS-1$

	String IRX_EXTENSION				= ".irx";							//$NON-NLS-1$
    String ZIP_EXTENSION                = ".zip";                           //$NON-NLS-1$
	String SAST							= "Static Analyzer";				//$NON-NLS-1$
	String STATIC_ANALYZER				= "StaticAnalyzer";					//$NON-NLS-1$

	String PREPARE						= "prepare";						//$NON-NLS-1$
	String PREPARE_ONLY					= "prepareOnly";					//$NON-NLS-1$
	String LOG_LOCATION					= "logDir";							//$NON-NLS-1$
	String SAVE_LOCATION				= "irxDir";							//$NON-NLS-1$
	String CONFIG_FILE					= "configFile";						//$NON-NLS-1$
	String DEBUG						= "debug";							//$NON-NLS-1$
	String VERBOSE						= "verbose";						//$NON-NLS-1$
	String THIRD_PARTY					= "thirdParty";						//$NON-NLS-1$
        String OPEN_SOURCE_ONLY                                  = "openSourceOnly";                                     //$NON-NLS-1$
        String SOURCE_CODE_ONLY                                  = "sourceCodeOnly";                                     //$NON-NLS-1$
    	String SCAN_SPEED                                        = "scanSpeed";                                          //$NON-NLS-1$
    	String OPT_SCAN_SPEED                                    = "-s";                                                 //$NON-NLS-1$
    	String OPT_NAME						= "-n";								//$NON-NLS-1$
    	String NORMAL						= "normal";								//$NON-NLS-1$
    	String FAST						= "fast";								//$NON-NLS-1$
    	String FASTER						= "faster";								//$NON-NLS-1$
    	String FASTEST						= "fastest";								//$NON-NLS-1$
    	String SIMPLE						= "simple";								//$NON-NLS-1$
    	String BALANCED						= "balanced";								//$NON-NLS-1$
    	String DEEP						= "deep";								//$NON-NLS-1$
    	String THOROUGH						= "thorough";								//$NON-NLS-1$
	String OPT_SAVE_LOCATION			= "-d";								//$NON-NLS-1$
	String OPT_LOG_LOCATION				= "-l";								//$NON-NLS-1$
	String OPT_CONFIG					= "-c";								//$NON-NLS-1$
	String OPT_THIRD_PARTY				= "-t";								//$NON-NLS-1$
	String OPT_VERBOSE					= "-v";								//$NON-NLS-1$
	String OPT_DEBUG					= "-X";								//$NON-NLS-1$
        String OPT_OPEN_SOURCE_ONLY                             = "-oso";                                                       //$NON-NLS-1$
	String OPT_SOURCE_CODE_ONLY                             = "-sco";                                                       //$NON-NLS-1$

	//Messages
	String DONE							= "message.done";					//$NON-NLS-1$
	String DOWNLOAD_COMPLETE			= "message.download.complete";		//$NON-NLS-1$
	String DOWNLOADING_CLIENT			= "message.downloading.client";		//$NON-NLS-1$
	String EXTRACTING_CLIENT			= "message.extracting.client";		//$NON-NLS-1$
	String PREPARING_IRX				= "message.preparing.irx";			//$NON-NLS-1$
	String SACLIENT_OUTDATED			= "message.saclient.old";			//$NON-NLS-1$
	String SERVER_UNAVAILABLE			= "message.server.unavailable";		//$NON-NLS-1$
	
	//Errors
	String IRX_MISSING					= "error.irx.missing";				//$NON-NLS-1$
	String ERROR_CHECKING_SACLIENT_VER 	= "error.checking.local.version";	//$NON-NLS-1$
	String ERROR_DOWNLOADING_CLIENT 	= "error.download.client";			//$NON-NLS-1$
	String ERROR_GENERATING_IRX			= "error.generating.irx";			//$NON-NLS-1$
    String ERROR_GENERATING_ZIP         = "error.generating.zip";           //$NON-NLS-1$
	String ERROR_SUBMITTING_IRX			= "error.submitting.irx";			//$NON-NLS-1$
	String DOWNLOAD_OUT_OF_MEMORY		= "error.out.of.memory";			//$NON-NLS-1$
}
