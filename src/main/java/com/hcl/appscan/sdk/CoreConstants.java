/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024, 2025.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk;

public interface CoreConstants {

	String DEFAULT_SERVER				= "https://cloud.appscan.com";							//$NON-NLS-1$
	
	//Technologies
	String DYNAMIC_TECH					= "DynamicAnalyzer";									//$NON-NLS-1$
	String SCA_TECH						= "ScaAnalyzer";										//$NON-NLS-1$
	String STATIC_TECH					= "StaticAnalyzer";										//$NON-NLS-1$
	
	String APP_ID						= "AppId";												//$NON-NLS-1$
	String EMAIL_NOTIFICATION			= "EnableMailNotification";								//$NON-NLS-1$
	String PERSONAL_SCAN 				= "Personal";											//$NON-NLS-1$
	String FILE_ID 						= "FileId"; 											//$NON-NLS-1$
	String FILE_TO_UPLOAD 				= "fileToUpload";										//$NON-NLS-1$
	String UPLOADED_FILE 				= "uploadedFile";										//$NON-NLS-1$
	String ID							= "Id";													//$NON-NLS-1$
        String SCAN_ID                                                  = "ScanId";                                                                                             //$NON-NLS-1$
	String KEY							= "Key";												//$NON-NLS-1$
	String LATEST_EXECUTION				= "LatestExecution";									//$NON-NLS-1$
	String LOCALE						= "Locale";												//$NON-NLS-1$
	String MESSAGE						= "Message";											//$NON-NLS-1$
	String NAME							= "Name";												//$NON-NLS-1$
	String PRESENCE_NAME				= "PresenceName";										//$NON-NLS-1$
	String SCAN_NAME					= "ScanName";											//$NON-NLS-1$
	String SCANNER_TYPE					= "type";												//$NON-NLS-1$
	String STATUS						= "Status";												//$NON-NLS-1$
	String TARGET						= "target";												//$NON-NLS-1$
	String OPEN_SOURCE_ONLY				= "openSourceOnly";										//$NON-NLS-1$
	String INCLUDE_SCA					= "includeSCA";											//$NON-NLS-1$
	String VERSION_NUMBER				= "VersionNumber";										//$NON-NLS-1$
	String USER_MESSAGE					= "UserMessage";										//$NON-NLS-1$
	String IS_VALID						= "IsValid";											//$NON-NLS-1$
	String SOURCE_CODE_ONLY				= "sourceCodeOnly";										//$NON-NLS-1$
	String SOFTWARE_COMPOSITION_ANALYZER= "Software Composition Analyzer";                     	//$NON-NLS-1$
	String SCA							= "Sca";                                               	//$NON-NLS-1$

	String CREATE_IRX					= "createIRX";											//$NON-NLS-1$
	String UPLOAD_DIRECT				= "uploadDirect";										//$NON-NLS-1$
	String BINDING_ID					= "Bindingid";											//$NON-NLS-1$
    String APPSCAN_OPTS                 = "APPSCAN_OPTS";                                       //$NON-NLS-1$
	String BLUEMIX_SERVER               = "BLUEMIX_SERVER";                                     //$NON-NLS-1$
	String KEY_ID						= "KeyId";												//$NON-NLS-1$
	String KEY_SECRET					= "KeySecret";											//$NON-NLS-1$
	String PASSWORD						= "Password";											//$NON-NLS-1$
	String TOKEN						= "Token";												//$NON-NLS-1$
	String USERNAME						= "Username";											//$NON-NLS-1$

	String CHARSET 						= "charset"; 											//$NON-NLS-1$
	String UTF8 						= "utf-8";								 				//$NON-NLS-1$

	String CONTENT_DISPOSITION 			= "Content-Disposition";				 				//$NON-NLS-1$
	String CONTENT_LENGTH				= "Content-Length";				 						//$NON-NLS-1$
	String CONTENT_TYPE					= "Content-Type";		 								//$NON-NLS-1$
	String CLIENT_TYPE					= "ClientType";		 									//$NON-NLS-1$
	
	String API_ENV						= "/api/v2";				 							//$NON-NLS-1$
	String API_ENV_LATEST				= "/api/v4";				 							//$NON-NLS-1$
	String API_BLUEMIX					= "Bluemix";					 						//$NON-NLS-1$
	String API_BLUEMIX_LOGIN 			= API_ENV + "/Account/BluemixLogin";					//$NON-NLS-1$
	String API_KEY_LOGIN				= API_ENV_LATEST + "/Account/ApiKeyLogin";				//$NON-NLS-1$
	String API_LOGOUT					= API_ENV + "/Account/Logout";							//$NON-NLS-1$
	String API_APPS						= API_ENV_LATEST + "/Apps"; 							//$NON-NLS-1$
	String API_PRESENCES				= API_ENV_LATEST + "/Presences";						//$NON-NLS-1$
	String API_PRESENCES_ID				= API_ENV_LATEST + "/Presences/%s";						//$NON-NLS-1$
	String API_PRESENCES_NEW_KEY		= API_ENV_LATEST + "/Presences/%s/NewKey";				//$NON-NLS-1$
	String API_BASIC_DETAILS			= API_ENV_LATEST + "/Scans";							//$NON-NLS-1$
	String API_SCANNER_DETAILS			= API_ENV_LATEST + "/Scans/%s/%s";								//$NON-NLS-1$
	String API_FILE_UPLOAD				= API_ENV_LATEST + "/FileUpload";						//$NON-NLS-1$
	String API_SCAN						= API_ENV + "/%s";										//$NON-NLS-1$
	String API_SCANNER					= API_ENV_LATEST + "/Scans/%s";							//$NON-NLS-1$
        String API_RESCAN					= API_ENV_LATEST + "/Scans/%s/Executions";							//$NON-NLS-1$
	String API_SCANS					= API_ENV + "/Scans";									//$NON-NLS-1$
	String API_NONCOMPLIANT_ISSUES 		= API_ENV + "/Scans/%s/NonCompliantIssues";				//$NON-NLS-1$
	String API_SCANS_REPORT				= API_ENV_LATEST + "/Scans/%s/Report/%s";				//$NON-NLS-1$
	String API_REPORT_SELECTED_ISSUES   = API_ENV_LATEST + "/Reports/Security/%s/%s";			//$NON-NLS-1$
	String API_DOWNLOAD_REPORT          = API_ENV_LATEST + "/Reports/%s/Download";				//$NON-NLS-1$
	String API_SACLIENT_DOWNLOAD		= API_ENV_LATEST + "/Tools/SAClientUtil?os=%s"; 		//$NON-NLS-1$
	String API_SACLIENT_VERSION			= API_ENV_LATEST + "/Tools/SAClientUtil?os=%s&meta=%s"; //$NON-NLS-1$
	String API_KEY_PATH					= "/api/ideclientuilogin";								//$NON-NLS-1$
	String API_REPORT_STATUS			= API_ENV_LATEST + "/Reports";							//$NON-NLS-1$
	String API_ISSUES_COUNT				= API_ENV_LATEST + "/Issues/%s/%s";						//$NON-NLS-1$
	String API_REGIONS					= API_ENV_LATEST + "/Utils/Regions";					//$NON-NLS-1$
	String API_IS_VALID_URL				= API_ENV_LATEST + "/Scans/IsValidUrl";					//$NON-NLS-1$
	String API_AUTHENTICATION			= API_ENV_LATEST + "/Account/IsAuthenticated";			//$NON-NLS-1$
	String API_TENANT_INFO				= API_ENV_LATEST + "/Account/TenantInfo";				//$NON-NLS-1$
	String API_EXECUTION_DETAILS		        = API_ENV_LATEST + "/Scans/%s/Executions";				    //$NON-NLS-1$

	String DEFAULT_RESULT_NAME			= "asoc_results";										//$NON-NLS-1$
	String SACLIENT_INSTALL_DIR			= "SAClientInstall";									//$NON-NLS-1$
	String SKIP_UPDATE					= "skipUpdate";											//$NON-NLS-1$

	String RUNNING						= "Running";											//$NON-NLS-1$
	String WAITING_TO_RUN				= "Waiting to Run";										//$NON-NLS-1$
	String STARTING					    = "Starting";											//$NON-NLS-1$
	String INQUEUE 					    = "InQueue"; 											//$NON-NLS-1$
	String READY						= "Ready";												//$NON-NLS-1$
	String FAILED						= "Failed";												//$NON-NLS-1$
	String PAUSING						= "Pausing";											//$NON-NLS-1$
	String PAUSED						= "Paused";												//$NON-NLS-1$
	String SUSPENDED					= "Suspended";											//$NON-NLS-1$
	String UNKNOWN						= "Unknown";											//$NON-NLS-1$
	String INCOMPLETE					= "Incomplete";											//$NON-NLS-1$
	String SERVER_URL					= "serverURL";											//$NON-NLS-1$
	String ACCEPT_INVALID_CERTS			= "acceptInvalidCerts";									//$NON-NLS-1$

	String TOTAL_ISSUES					= "NIssuesFound";										//$NON-NLS-1$
	String CRITICAL_ISSUES				= "NCriticalIssues";									//$NON-NLS-1$
	String HIGH_ISSUES					= "NHighIssues";										//$NON-NLS-1$
	String MEDIUM_ISSUES				= "NMediumIssues";										//$NON-NLS-1$
	String LOW_ISSUES					= "NLowIssues";											//$NON-NLS-1$
	String INFO_ISSUES					= "NInfoIssues";										//$NON-NLS-1$
	String ITEMS					    = "Items";										        //$NON-NLS-1$

	String CREATE_SCAN_SUCCESS			= "message.created.scan";								//$NON-NLS-1$
	String SCAN_OVERVIEW				= "message.scan.overview";								//$NON-NLS-1$
	String RESCAN_SUCCESS				= "message.rescan";								        //$NON-NLS-1$
	String RESCAN_OVERVIEW				= "message.rescan.overview";								//$NON-NLS-1$
	String DOWNLOADING_CLIENT			= "message.downloading.client";							//$NON-NLS-1$
	String EXECUTING_SCAN				= "message.running.scan";								//$NON-NLS-1$
	String UPLOADING_FILE				= "message.uploading.file";								//$NON-NLS-1$
	String SUSPEND_JOB_BYUSER		    = "message.suspend.job.byuser";                         //$NON-NLS-1$

	String REGIONS						= "Regions";											//$NON-NLS-1$
	String DEFAULT_REGION				= "DefaultRegion";										//$NON-NLS-1$
	String URL							= "Url";												//$NON-NLS-1$
	
	String ERROR_AUTHENTICATING			= "error.authenticating";								//$NON-NLS-1$
	String ERROR_DOWNLOADING_CLIENT 	= "error.download.client";								//$NON-NLS-1$
	String ERROR_GETTING_DETAILS		= "error.getting.details";								//$NON-NLS-1$
	String ERROR_GETTING_DETAILS_SCAN_ID= "error.getting.details.scan.id";						//$NON-NLS-1$
	String ERROR_GETTING_RESULT			= "error.getting.result";								//$NON-NLS-1$
	String ERROR_GENERATING_REPORT      = "error.generating.report";                            //$NON-NLS-1$
	String ERROR_INVALID_APP			= "error.invalid.app";									//$NON-NLS-1$
	String ERROR_INVALID_OPTIONS		= "error.invalid.opts";									//$NON-NLS-1$
	String ERROR_LOADING_APPS			= "error.loading.apps";									//$NON-NLS-1$
	String ERROR_LOGIN_EXPIRED			= "login.token.expired";								//$NON-NLS-1$
	String ERROR_INVALID_JOB_ID			= "error.invalid.job.id";								//$NON-NLS-1$
	String ERROR_SUBMITTING_SCAN		= "error.submit.scan";									//$NON-NLS-1$
	String ERROR_UPLOADING_FILE			= "error.upload.file";									//$NON-NLS-1$
	String ERROR_GETTING_INFO			= "error.getting.info";									//$NON-NLS-1$
	String ERROR_URL_VALIDATION			= "error.url.validation";								//$NON-NLS-1$
	String FORMAT_PARAMS				= "FormatParams";								        //$NON-NLS-1$
	String ERROR_GETTING_SCANLOG		= "error.getting.scanlog";								//$NON-NLS-1$
	String ERROR_CANCEL_RESCAN  		= "error.cancel.rescan";								//$NON-NLS-1$
	// ASE Status Messages
	String CREATING_JOB                 = "message.creating.job";                               //$NON-NLS-1$
	String CREATE_JOB_SUCCESS			= "message.created.job";								//$NON-NLS-1$
	String ERROR_CREATE_JOB  			= "error.create.job";									//$NON-NLS-1$
	String UPDATE_JOB				= "message.update.job";								//$NON-NLS-1$
	String ERROR_UPDATE_JOB  			= "error.update.job";									//$NON-NLS-1$
	String EXECUTING_JOB				= "message.running.job";								//$NON-NLS-1$
	String EXECUTE_JOB_SUCCESS    		= "message.executed.job";								//$NON-NLS-1$
	String ERROR_EXECUTE_JOB  			= "error.execute.job";									//$NON-NLS-1$
	String RESULTS_UNAVAILABLE		    = "message.results.unavailable";						//$NON-NLS-1$
	String ERROR_INVALID_DETAILS        = "error.invalid.details";                              //$NON-NLS-1$

    // ASE APIs
    String ASE_API                      = "/api";												//$NON-NLS-1$
    String ASE_APPS                     = ASE_API + "/applications";							//$NON-NLS-1$
    String ASE_FOLDERS                  = ASE_API + "/folders";									//$NON-NLS-1$
    String ASE_TEST_POLICIES            = ASE_API + "/testPolicies";							//$NON-NLS-1$
    String ASE_AGENT_SERVER             = ASE_API + "/agentServer";								//$NON-NLS-1$
    String ASE_UPDSCANT                 = ASE_API + "/jobs/%s/dastconfig/updatescant";			//$NON-NLS-1$
    String ASE_UPDTRAFFIC               = ASE_API + "/jobs/%s/dastconfig/updatetraffic/%s";		//$NON-NLS-1$
    String ASE_UPDTAGENT     			= ASE_API + "/jobs/%s/designateAgentServer/%s";			//$NON-NLS-1$
    String ASE_SCAN_TYPE		        = ASE_API + "/jobs/scantype";							//$NON-NLS-1$
    String ASE_LOGIN_API                = ASE_API + "/keylogin/apikeylogin";					//$NON-NLS-1$
    String ASE_KEY_ID                   = "keyId";												//$NON-NLS-1$
    String ASE_KEY_SECRET               = "keySecret";											//$NON-NLS-1$
    String ASE_NAME_ATTRIBUTE           = "name";												//$NON-NLS-1$
    String ASE_ID_ATTRIBUTE             = "id";													//$NON-NLS-1$
    String ASE_CREATEJOB_TEMPLATE_ID    = ASE_API + "/jobs/%s/dastconfig/createjob";			//$NON-NLS-1$
    String ASE_GET_JOB                  = ASE_API + "/jobs/%s";									//$NON-NLS-1$
    String ASE_RUN_JOB_ACTION           = ASE_API +"/jobs/%s/actions";							//$NON-NLS-1$
    String ASE_REPORTPACK               = ASE_API + "/folderitems/%s/reportPack";				//$NON-NLS-1$
    String ASE_REPORTS                  = ASE_API + "/folderitems/%s/reports";					//$NON-NLS-1$
    String ASE_GET_FOLDERITEMS          = ASE_API + "/folderitems/%s";							//$NON-NLS-1$
    String ASE_UPLOADED_FILE            = "uploadedfile";										//$NON-NLS-1$
    String ASE_CURRENTUSER_V2           = ASE_API + "/currentuser_v2";							//$NON-NLS-1$
    String ASE_GET_FOLDER_ITEMS_STATISTICS	= ASE_API + "/folderitems/%s/statistics";			//$NON-NLS-1$

    String UNAUTHORIZED_ACTION			= "UNAUTHORIZED_ACTION";								//$NON-NLS-1$

	String API_SCANS_SCANLOGS			= API_ENV_LATEST + "/Scans/ScanLogs/%s";				//$NON-NLS-1$

}
