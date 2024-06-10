/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2022, 2023.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.DefaultProgress;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import com.hcl.appscan.sdk.utils.ArchiveUtil;
import com.hcl.appscan.sdk.utils.FileUtil;
import com.hcl.appscan.sdk.utils.ServiceUtil;
import com.hcl.appscan.sdk.utils.SystemUtil;

public class SAClient implements SASTConstants {

	private static final File DEFAULT_INSTALL_DIR = new File(System.getProperty("user.home"), ".appscan"); //$NON-NLS-1$ //$NON-NLS-2$
	private static final String SACLIENT = "SAClientUtil"; //$NON-NLS-1$
	private static final String VERSION_INFO = "version.info"; //$NON-NLS-1$
	
	private IProgress m_progress;
	private ProcessBuilder m_builder;
	private File m_installDir;
	private Proxy m_proxy;
	
	public SAClient() {
		this(new DefaultProgress(), Proxy.NO_PROXY);
	}
	
	public SAClient(Proxy proxy) {
		this(new DefaultProgress(), proxy);
	}
	
	public SAClient(IProgress progress) {
		this(progress, Proxy.NO_PROXY);
	}
	
	public SAClient(IProgress progress, Proxy proxy) {
		m_progress = progress;
		String install = System.getProperty(CoreConstants.SACLIENT_INSTALL_DIR);
		m_installDir = install == null ? DEFAULT_INSTALL_DIR : new File(install);
		m_proxy = proxy;
	}
	
	/**
	 * Run the SAClient
	 * @param workingDir The directory where the SAClient will run.
	 * @param properties A Map of properties that will be converted to program arguments.
	 * @return The process exit code, 0 for success.
	 * @throws IOException If an error occurs.
	 * @throws ScannerException If an error occurs.
	 */
	public int run(String workingDir, Map<String, String> properties) throws IOException, ScannerException {
		return runClient(workingDir,
						 getClientArgs(properties),
						 properties.get(APPSCAN_IRGEN_CLIENT),
						 properties.get(APPSCAN_CLIENT_VERSION),
						 properties.get(IRGEN_CLIENT_PLUGIN_VERSION), properties.get(CoreConstants.SERVER_URL), properties.get(CoreConstants.ACCEPT_INVALID_CERTS));
	}

	/**
	 * Run the SAClient
	 * @param workingDir The directory where the SAClient will run.
	 * @param args A List of program arguments.
	 * @return The process exit code, 0 for success.
	 * @throws IOException If an error occurs.
	 * @throws ScannerException If an error occurs.
	 * @deprecated Use {@link #run(String, Map)} instead.
	 */
	@Deprecated
	public int run(String workingDir, List<String> args) throws IOException, ScannerException {
		return runClient(workingDir, args, "", "", "");
	}

    	private int runClient(String workingDir, List<String> args, String irGenClient, String clientVersion, String irgenClientPluginVersion) throws IOException, ScannerException{
		 return runClient(workingDir,args,irGenClient,clientVersion,irgenClientPluginVersion, "", "");
        }
		
	private int runClient(String workingDir, List<String> args, String irGenClient, String clientVersion, String irgenClientPluginVersion, String serverURL, String acceptInvalidCerts) throws IOException, ScannerException {
		List<String> arguments = new ArrayList<String>();
		arguments.add(getClientScript(serverURL,acceptInvalidCerts));
		arguments.addAll(args);
		m_builder = new ProcessBuilder(arguments);
		m_builder.directory(new File(workingDir));
		m_builder.redirectErrorStream(true);
		if (irGenClient != null && !irGenClient.isEmpty())
			m_builder.environment().put(APPSCAN_IRGEN_CLIENT, irGenClient);
		
		if (clientVersion != null && !clientVersion.isEmpty())
			m_builder.environment().put(APPSCAN_CLIENT_VERSION, clientVersion);
		
		if (irgenClientPluginVersion != null && !irgenClientPluginVersion.isEmpty())
			m_builder.environment().put(IRGEN_CLIENT_PLUGIN_VERSION, irgenClientPluginVersion);
			
		m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(PREPARING_IRX, getLocalClientVersion())));
        if((serverURL !=null) && !serverURL.isEmpty()){
            String options = System.getenv(CoreConstants.APPSCAN_OPTS) == null ? "" : System.getenv(CoreConstants.APPSCAN_OPTS);
            if("true".equals(acceptInvalidCerts)) {
                options += " -Dacceptssl";
            }
            m_builder.environment().put(CoreConstants.APPSCAN_OPTS, options);
        }

                final Process proc = m_builder.start();
		    new Thread(new Runnable() {
			@Override
			public void run() {
				BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String line;
				try {
					while((line = reader.readLine()) != null)
						m_progress.setStatus(new Message(Message.INFO, line));
				}
				catch(IOException e) {
					m_progress.setStatus(e);
				} 
				finally {
					try {
						reader.close();
					} catch (IOException e) {
						m_progress.setStatus(e);
					}
				}
			}
		}).start();
		
		try {
			proc.waitFor();
		} catch (InterruptedException e) {
			m_progress.setStatus(e);
			return -1;
		}

		return proc.exitValue();
	}
	
	/**
	 * Gets the absolute path to the "appscan" script for running the IRGen process, downloading the package if it's
	 * not found or if the current version is out of date.
	 * @return The absolute path to the "appscan" script.
	 * @throws IOException If an error occurs.
	 * @throws ScannerException If an error occurs getting the client.
	 */
        public String getClientScript() throws IOException, ScannerException {
            return getClientScript("","");
        }

        public String getClientScript(String serverURL, String acceptInvalidCerts) throws IOException, ScannerException {
		//See if we already have the client package.
		String scriptPath = "bin" + File.separator + getScriptName(); //$NON-NLS-1$
		File install = findClientInstall();
		
		if(install != null && new File(install, scriptPath).isFile() && !shouldUpdateClient(serverURL))
			return new File(install, scriptPath).getAbsolutePath();
		
		//Download it.
		m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(DOWNLOADING_CLIENT)));
		if(install != null && install.isDirectory())
			deleteDirectory(install);
		
		File clientZip = new File(m_installDir, SACLIENT + ".zip"); //$NON-NLS-1$
		if(clientZip.isFile())
			clientZip.delete();
		
		try {
			ServiceUtil.getSAClientUtil(clientZip, m_proxy, serverURL, acceptInvalidCerts);
		} catch(OutOfMemoryError e) {
			throw new ScannerException(Messages.getMessage(DOWNLOAD_OUT_OF_MEMORY));
		} catch(IOException e) {
			throw new ScannerException(Messages.getMessage(ERROR_DOWNLOADING_CLIENT, e.getLocalizedMessage()));
		}
		
		if(clientZip.isFile()) {
			m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(DOWNLOAD_COMPLETE)));
			m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(EXTRACTING_CLIENT)));
			ArchiveUtil.unzip(clientZip, m_installDir);
			m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(DONE)));
		}

		return new File(findClientInstall(), scriptPath).getAbsolutePath();
	}
	
	private String getScriptName() {
		return SystemUtil.isWindows() ? WIN_SCRIPT : UNIX_SCRIPT;
	}
	
	public boolean majorVersionChanged() throws IOException {
		String serverMajorVersion = ServiceUtil.getSAClientVersion(m_proxy);
		String localMajorVersion = getLocalClientVersion();
		
		if (serverMajorVersion != null && localMajorVersion != null) {
			serverMajorVersion = serverMajorVersion.substring(0, 1);
			localMajorVersion = localMajorVersion.substring(0, 1);
			return !localMajorVersion.equals(serverMajorVersion);
		}
		else {
			m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(SERVER_UNAVAILABLE)));
			return false;
		}
	}

    	public boolean shouldUpdateClient() throws IOException {
            	return shouldUpdateClient("");
    	}
	
	public boolean shouldUpdateClient(String serverURL) throws IOException {
		String serverVersion = ServiceUtil.getSAClientVersion(m_proxy,serverURL);
		String localVersion = getLocalClientVersion();

		if(compareVersions(localVersion, serverVersion) && System.getProperty(CoreConstants.SKIP_UPDATE) == null) {
			m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(SACLIENT_OUTDATED, localVersion, serverVersion)));
			return true;
		}
		return false;
	}
	
	private File findClientInstall() {
		if(!m_installDir.isDirectory())
			return null;
		
		File files[] = m_installDir.listFiles(new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.startsWith(SACLIENT) && new File(dir, name).isDirectory();
			}
		});
		
		//If there's more than 1 directory, we need to determine the latest. Delete any older directories that are found.
		if(files.length > 1) {
			File latest = files[0];
			String latestVersion = getVersionFromString(latest.getName());
			
			for(int i = 1; i < files.length; i++) {
				String otherVersion = getVersionFromString(files[i].getName());
				if(compareVersions(latestVersion, otherVersion)) {
					deleteDirectory(latest);
					latest = files[i];
					latestVersion = getVersionFromString(latest.getName());
				}
				else
					deleteDirectory(files[i]);
			}
			
			return latest;
		}
		else
			return files.length == 0 ? null : files[0];
	}
	
	private String getLocalClientVersion() {
		File versionInfo = new File(findClientInstall(), VERSION_INFO);
		String version = null;
		BufferedReader reader = null;
		
		try {
			reader = new BufferedReader(new FileReader(versionInfo));
			version = reader.readLine(); //The version is the first line of the version.info file.
		} catch (IOException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_CHECKING_SACLIENT_VER, e.getLocalizedMessage())));
		} finally {
			try {
				if(reader != null)
					reader.close();
			} catch (IOException e) {
			}
		}
		return version;
	}
	
	private void deleteDirectory(File directory) {
		if(!directory.isDirectory())
			directory.delete();
		
		for(File file : directory.listFiles()) {
			if(file.isDirectory())
				deleteDirectory(file);
			else
				file.delete();
		}
		directory.delete();
	}
	
	/**
	 * Given a Map of properties, returns a List of arguments.
	 * @param properties The Map of properties.
	 * @return A list of command line arguments for the SAClient to use
	 */
	private List<String> getClientArgs(Map<String, String> properties) {
		ArrayList<String> args = new ArrayList<String>();
		args.add(PREPARE);
		
		if(properties.containsKey(CoreConstants.SCAN_NAME)) {
			args.add(OPT_NAME);
			args.add(FileUtil.getValidFilename(properties.get(CoreConstants.SCAN_NAME)));
		}
		if(properties.containsKey(LOG_LOCATION)) {
			args.add(OPT_LOG_LOCATION);
			args.add(properties.get(LOG_LOCATION));
		}
		if(properties.containsKey(SAVE_LOCATION)) {
			args.add(OPT_SAVE_LOCATION);
			args.add(properties.get(SAVE_LOCATION));
		}
		if(properties.containsKey(CONFIG_FILE)) {
			args.add(OPT_CONFIG);
			args.add(properties.get(CONFIG_FILE));
		}
		if(properties.containsKey(DEBUG) || System.getProperty(DEBUG.toUpperCase()) != null)
			args.add(OPT_DEBUG);
		if(properties.containsKey(VERBOSE))
			args.add(OPT_VERBOSE);
		if(properties.containsKey(THIRD_PARTY) || System.getProperty(THIRD_PARTY) != null)
			args.add(OPT_THIRD_PARTY);
		if (properties.containsKey(OPEN_SOURCE_ONLY) || System.getProperty(OPEN_SOURCE_ONLY) != null)
			args.add(OPT_OPEN_SOURCE_ONLY);
                if (properties.containsKey(SOURCE_CODE_ONLY) || System.getProperty(SOURCE_CODE_ONLY) != null)
                        args.add(OPT_SOURCE_CODE_ONLY);
                if (!properties.containsKey(CoreConstants.INCLUDE_SCA) && properties.get(CoreConstants.SCANNER_TYPE).equals(CoreConstants.SOFTWARE_COMPOSITION_ANALYZER))
                    args.add(OPT_OPEN_SOURCE_ONLY);
                if(properties.containsKey(SCAN_SPEED)){
                    	args.add(OPT_SCAN_SPEED);
		if(properties.containsKey(SECRETS_ENABLED) || System.getProperty(SECRETS_ENABLED) != null)
			args.add(OPT_SECRETS_ENABLED);
		if(properties.containsKey(SECRETS_ONLY) || System.getProperty(SECRETS_ONLY) != null)
			args.add(OPT_SECRETS_ONLY);
                        //it is being used to have the same values in the freestyle & pipeline projects
                        if(properties.get(SCAN_SPEED).equals(NORMAL)){
                            args.add(THOROUGH);
                        } else if (properties.get(SCAN_SPEED).equals(FAST)) {
                            args.add(DEEP);
                        } else if (properties.get(SCAN_SPEED).equals(FASTER)) {
                            args.add(BALANCED);
                        } else if (properties.get(SCAN_SPEED).equals(FASTEST)) {
                            args.add(SIMPLE);
                        } else {
                            args.add(properties.get(SCAN_SPEED));
                        }
                }
		
		return args;
	}

	private boolean compareVersions(String baseVersion, String newVersion) {
		if(baseVersion == null)
			return true;
		
		if(baseVersion != null && newVersion != null) {
			String[] base = baseVersion.split("\\."); //$NON-NLS-1$
			String[] next = newVersion.split("\\."); //$NON-NLS-1$

			try {
				for(int iter = 0; iter < base.length && iter < next.length; iter++) {
					int lVersion = Integer.parseInt(base[iter]);
					int sVersion = Integer.parseInt(next[iter]);
					
					if (((iter==0) && lVersion<sVersion)
							|| (iter==1 && lVersion<sVersion)
							|| (iter==2 && lVersion<sVersion)) {
						return true;
					}
				}
			} catch (NumberFormatException e) {
				return false;
			}
		}
		return false;
	}
	
	private String getVersionFromString(String name) {
		String version = name.substring(SACLIENT.length());
		if(version.trim().startsWith(".")) //$NON-NLS-1$
			version = version.substring(1);
		return version;
	}
}
