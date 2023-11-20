/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2023. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.http;

import org.apache.wink.json4j.JSON;
import org.apache.wink.json4j.JSONObject;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpClient {
	
	private String m_boundary;
	private long m_totalMultipartLength;
	private long m_uploadedMultipartLength;
    private static final String CR_LF = "\r\n"; //$NON-NLS-1$
    private static final String TWO_HYPHENS = "--"; //$NON-NLS-1$
    
    private IHttpProgress m_progressAdapter;
    private Proxy m_proxy;
    private boolean m_bypassSSL;
	
	
	public enum Method {
		GET, POST, PUT, DELETE;
	}
	
	public HttpClient(IHttpProgress progressAdapter, Proxy proxy, boolean bypassSSL) {
		m_progressAdapter = progressAdapter;
		m_proxy = proxy;
		m_bypassSSL = bypassSSL;
	}
	
	public HttpClient() {
		this(new DefaultHttpProgress(), Proxy.NO_PROXY, false);
	}
	
	public HttpClient(Proxy proxy) {
		this(new DefaultHttpProgress(), proxy, false);
	}
	
	public HttpClient(Proxy proxy, boolean bypassSSL) {
		this(new DefaultHttpProgress(), proxy, bypassSSL);
	}
	
	public HttpClient(IHttpProgress progressAdapter) {
		this(progressAdapter, Proxy.NO_PROXY, false);
	}
	
	public HttpClient(IHttpProgress progressAdapter, boolean bypassSSL) {
		this(progressAdapter, Proxy.NO_PROXY, bypassSSL);
	}
	
	// ==============================
	// HTTP request methods
	// ==============================

	/**
	 * Submit a get request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param body An optional request body or payload as a string.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse get(String url,
			Map<String, String> headerProperties, String body)
			throws IOException {
		return makeRequest(Method.GET, url, headerProperties, body);
	}

	/**
	 * Submit a post request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param body An optional request body or payload as a string.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse post(String url,
			Map<String, String> headerProperties, String body)
			throws IOException {
		if (body==null) body = ""; //$NON-NLS-1$
		return makeRequest(Method.POST, url, headerProperties, body);
	}

    /**
     * Submit a post request.
     *
     * @param url The URL string.
     * @param headerProperties An optional Map of header properties.
     * @param params An optional Map of properties.
     * @return The response as a byte array.
     * @throws IOException If an error occurs.
     */
    public HttpResponse post(String url, Map<String, String> headerProperties, Map<String, String> params)
            throws IOException {
        Map<String, Object> objectMap = new HashMap<>();
        for (String key : params.keySet()) {
            String value = params.get(key);
            if (value != null) {
                if (value.equalsIgnoreCase("true")) {
                    objectMap.put(key, true);
                } else if (value.equalsIgnoreCase("false")) {
                    objectMap.put(key, false);
                } else {
                    // If the string is not "true" or "false," keep it as is
                    objectMap.put(key, value);
                }
            } else {
                // If the value is not a string, keep it as is
                objectMap.put(key, value);
            }
        }
        JSONObject json = new JSONObject(objectMap);
        String body = json.toString();
        return post(url, headerProperties, body);
    }

	/**
	 * Submit a put request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param body An optional request body or payload as a string.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse put(String url,
			Map<String, String> headerProperties, String body)
			throws IOException {
		return makeRequest(Method.PUT, url, headerProperties, body);
	}

	/**
	 * Submit a delete request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param body An optional request body or payload as a string.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse delete(String url,
			Map<String, String> headerProperties, String body)
			throws IOException {
		return makeRequest(Method.DELETE, url, headerProperties, body);
	}
	
	/**
	 * Submit a form with parameters using the get request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param params An optional Map of parameters.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse getForm(String url,
			Map<String, String> headerProperties, Map<String, String> params)
			throws IOException {
		String body = buildQueryString(params);
		return get(url, headerProperties, body);
	}

	/**
	 * Submit a form with parameters using the post request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param params An optional Map of parameters.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse postForm(String url,
			Map<String, String> headerProperties, Map<String, String> params)
			throws IOException {
		String body = buildQueryString(params);
		return post(url, headerProperties, body);
	}

	/**
	 * Submit a form with parameters using the put request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param params An optional Map of parameters.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse putForm(String url,
			Map<String, String> headerProperties, Map<String, String> params)
			throws IOException {
		String body = buildQueryString(params);
		return put(url, headerProperties, body);
	}

	/**
	 * Submit a form with parameters using the delete request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param params An optional Map of parameters.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse deleteForm(String url,
			Map<String, String> headerProperties, Map<String, String> params)
			throws IOException {
		String body = buildQueryString(params);
		return delete(url, headerProperties, body);
	}
	
	/**
	 * Submit a multipart entity using the post request.
	 * 
	 * @param url The URL string.
	 * @param headerProperties An optional Map of header properties.
	 * @param parts A list of parts.
	 * @return The response as a byte array.
	 * @throws IOException If an error occurs.
	 */
	public HttpResponse postMultipart(String url,
			Map<String, String> headerProperties, List<HttpPart> parts)
			throws IOException {
		m_boundary = "*****"+Long.toString(System.currentTimeMillis())+"*****"; //$NON-NLS-1$ //$NON-NLS-2$
		headerProperties.put("Content-Type", "multipart/form-data; boundary=" + m_boundary); //$NON-NLS-1$ //$NON-NLS-2$
		return makeMultipartRequest(Method.POST, url, headerProperties, parts);
	}
	
	private HttpResponse makeMultipartRequest(Method method, String url,
			Map<String, String> headerProperties, List<HttpPart> parts)
					throws IOException {
		HttpsURLConnection conn = makeConnection(url, method, headerProperties);
				
		DataOutputStream outputStream = null;
		conn.setChunkedStreamingMode(1024);
		
		if (parts!=null && !parts.isEmpty()) {
			conn.setDoOutput(true);
			conn.setUseCaches(false);
			
			outputStream = new DataOutputStream(conn.getOutputStream());
			
			m_uploadedMultipartLength = 0;
			m_totalMultipartLength = getTotalPartsLength(parts);
			
			updateProgress();
			
			StringBuilder builder;
			Map<String, String> partHeaders;
			for (HttpPart part : parts) {
				builder = new StringBuilder();
				builder.append(TWO_HYPHENS+m_boundary+CR_LF);
				partHeaders = part.getPartHeaders();
				Iterator<String> headers = partHeaders.keySet().iterator();
				String header;
				while (headers.hasNext()) {
					header = headers.next();
					builder.append(header + ": " +partHeaders.get(header)+CR_LF); //$NON-NLS-1$
				}
				outputStream.writeBytes(builder.toString()+CR_LF);
				outputStream.flush();
				byte[] buffer = new byte[1024];
			    int bytesRead;
			    while ((bytesRead = part.getPartBodyInputStream().read(buffer)) != -1)
			    {
			    	outputStream.write(buffer, 0, bytesRead);
			    	m_uploadedMultipartLength += bytesRead;
					updateProgress();
			    }
				outputStream.writeBytes(CR_LF);
				outputStream.flush();
			}
			outputStream.writeBytes(TWO_HYPHENS+m_boundary+TWO_HYPHENS+CR_LF);
			outputStream.flush();
			updateProgress();
		}
		outputStream.flush();
		outputStream.close();
		
		m_progressAdapter.endProgress();
		
		return new HttpResponse(conn);
	}

	private HttpResponse makeRequest(Method method, String url,
			Map<String, String> headerProperties, String payload)
			throws IOException {
		HttpsURLConnection conn = makeConnection(url, method, headerProperties);

		// Write payload
		if (payload != null) {
			conn.setDoOutput(true);
			DataOutputStream writer = new DataOutputStream(
					conn.getOutputStream());
			writer.writeBytes(payload);
			writer.flush();
			writer.close();
		}
		
		return new HttpResponse(conn);
	}
	
	private HttpsURLConnection makeConnection(String url, Method method,
			Map<String, String> headerProperties) throws IOException {
		URL requestURL = new URL(url);
		HttpsURLConnection conn = null;
		conn = (HttpsURLConnection) requestURL.openConnection(m_proxy);
		conn.setRequestMethod(method.name());
		conn.setReadTimeout(0);
		if(m_bypassSSL) {
			bypassSSL(conn);
		}

		// HTTP headers
		if (headerProperties != null) {
			for (String key : headerProperties.keySet()) {
				conn.setRequestProperty(key, headerProperties.get(key));
			}
		}
		return conn;
	}
	
	private long getTotalPartsLength(List<HttpPart> parts) {
		long totalSize = 0;
		for (HttpPart part : parts) {
			totalSize += part.getPartLength();
		}
		return totalSize;
	}
	
	private void updateProgress() {
		int progress = (int) ((float)m_uploadedMultipartLength/m_totalMultipartLength*100);
		m_progressAdapter.setProgress(progress);
	}
	
	private String buildQueryString(Map<String, String> params) throws UnsupportedEncodingException {
	    StringBuilder result = new StringBuilder();
	    boolean first = true;

	    if (params == null)
	    	return ""; //$NON-NLS-1$
	    
	    Iterator<String> iter = params.keySet().iterator();
	    while (iter.hasNext()) {
	    	String key = iter.next();
	    	String value = params.get(key);
	        if (first)
	            first = false;
	        else
	            result.append("&"); //$NON-NLS-1$

	        result.append(URLEncoder.encode(key, "UTF-8")); //$NON-NLS-1$
	        result.append("="); //$NON-NLS-1$
	        result.append(URLEncoder.encode(value, "UTF-8")); //$NON-NLS-1$
	    }

	    return result.toString();
	}
	
	private void bypassSSL(HttpsURLConnection conn)  {
		conn.setHostnameVerifier(new HostnameVerifier() {
			@Override
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		});

		TrustManager[] trustManagers = new TrustManager[] { new X509TrustManager() {

			private X509Certificate[] x509Certificates = new X509Certificate[0];

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return x509Certificates;
			}

			@Override
			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				// do nothing
			}

			@Override
			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				// do nothing
			}
		}};

		try {
			SSLContext context = SSLContext.getInstance("TLSv1.2"); //$NON-NLS-1$
			context.init(null, trustManagers, null);
			conn.setSSLSocketFactory(context.getSocketFactory());
		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			//Ignore. The connection should fail.
		}
	}
}
