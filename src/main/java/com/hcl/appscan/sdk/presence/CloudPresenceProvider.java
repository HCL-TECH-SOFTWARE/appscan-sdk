/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.presence;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpClient;
import com.hcl.appscan.sdk.http.HttpResponse;
import com.hcl.appscan.sdk.logging.DefaultProgress;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;

public class CloudPresenceProvider implements IPresenceProvider, CoreConstants {

	private Map<String, String> m_presences;
	private IProgress m_progress;
	private IAuthenticationProvider m_authProvider;
	
	public CloudPresenceProvider(IAuthenticationProvider provider) {
		this(provider, new DefaultProgress());
	}
	
	public CloudPresenceProvider(IAuthenticationProvider provider, IProgress progress) {
		m_authProvider = provider;
		m_progress = progress;
	}
	
	@Override
	public Map<String, String> getPresences() {
		if(m_presences == null)
			loadPresences();
		return m_presences;
	}

	@Override
	public String getName(String id) {
		return getPresences().get(id);
	}

	@Override
	public boolean delete(String id) {
		if(!authenticated())
			return false;

		String url =  m_authProvider.getServer() + String.format(API_PRESENCES_ID, id);
		Map<String, String> headers = m_authProvider.getAuthorizationHeader(true);

		HttpClient client = new HttpClient(m_authProvider.getProxy());
		
		try {
			HttpResponse response = client.delete(url, headers, null);
			if(response.isSuccess())
				return true;
			handleError(response);
		}
		catch(IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage("error.deleting.presence", id)), e); //$NON-NLS-1$
		}
		
		return false;		
	}

	@Override
	public Map<String, String> getDetails(String id) {
		if(!authenticated())
			return null;
		String url =  m_authProvider.getServer() + API_PRESENCES+"?%24filter=Id%20eq%20"+id;
		Map<String, String> headers = m_authProvider.getAuthorizationHeader(true);
		Map<String, String> details = new HashMap<String, String>();

		HttpClient client = new HttpClient(m_authProvider.getProxy());
		try {
			HttpResponse response = client.get(url, headers, null);
			if(response.isSuccess()) {
				JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
				JSONArray array = json.getJSONArray("Items");
				if(array == null)
					return details;
				JSONObject presenceDetail = array.getJSONObject(0);
				for(Object key : presenceDetail.keySet())
					details.put((String)key, presenceDetail.getString((String)key));
			}
			else
				handleError(response);
		}
		catch(IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage("error.getting.presence.details", id)), e); //$NON-NLS-1$
		}
		return details;
	}

	@Override
	public String getNewKey(String id) {
		if(!authenticated())
			return null;
		
		String key = null;
		String url =  m_authProvider.getServer() + String.format(API_PRESENCES_NEW_KEY, id);
		Map<String, String> headers = m_authProvider.getAuthorizationHeader(true);

		HttpClient client = new HttpClient(m_authProvider.getProxy());
		
		try {
			HttpResponse response = client.get(url, headers, null);
			if(response.isSuccess()) {
				JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
				key = json.getString(KEY);
			}
			else
				handleError(response);
		}
		catch(IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage("error.getting.new.key", id)), e); //$NON-NLS-1$
		}
		
		return key;
	}
	
	private void loadPresences() {
		if(!authenticated())
			return;
		
		m_presences = new HashMap<String, String>();
		String url =  m_authProvider.getServer() + API_PRESENCES + "?fields=Name&sort=%2BName"; //$NON-NLS-1$
		Map<String, String> headers = m_authProvider.getAuthorizationHeader(true);
		headers.putAll(Collections.singletonMap("range", "items=0-999999")); //$NON-NLS-1$ //$NON-NLS-2$
		
		HttpClient client = new HttpClient(m_authProvider.getProxy());
		
		try {
			HttpResponse response = client.get(url, headers, null);
			
			if (response.isSuccess()) {
				JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
				JSONArray array = json.getJSONArray("Items");
				if(array == null)
					return;
				
				for(int i = 0; i < array.length(); i++) {
					JSONObject object = array.getJSONObject(i);
					String id = object.getString(ID);
					String name = object.getString(PRESENCE_NAME);
					m_presences.put(id, name);
				}
			}
			else
				handleError(response);
		}
		catch(IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage("error.loading.presences")), e); //$NON-NLS-1$
			m_presences = null;
		}
	}
	
	private void handleError(HttpResponse response) throws IOException, JSONException {
		JSONObject json = (JSONObject)response.getResponseBodyAsJSON();
		if(json != null && json.has(MESSAGE))
			m_progress.setStatus(new Message(Message.ERROR, json.getString(MESSAGE)));
		else
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage("error.service.general", response.getResponseCode()))); //$NON-NLS-1$
	}
	
	private boolean authenticated() {
		if(m_authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage("login.error"))); //$NON-NLS-1$
			return false;
		}
		return true;
	}
}
