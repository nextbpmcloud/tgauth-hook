package es.tangrambpm.liferay;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.IOUtils;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.struts.BaseStrutsAction;
import com.liferay.portal.kernel.templateparser.TransformException;
import com.liferay.portal.kernel.util.WebKeys;
import com.liferay.portal.theme.ThemeDisplay;
import com.liferay.portal.util.PortalUtil;

/**
 * @author erevilla
 *
 */
public class AuthenticationAction extends BaseStrutsAction {
	private static Log log = LogFactoryUtil.getLog(AuthenticationAction.class);
	// CMD can now be an URL or command line (needs new afirmaproxy)
	private static final String CMD = Utils.readProp("cmd", "http://tangramdt:5000/certificate/check/");
	public static final String SSO_PROVIDER_URL = Utils.readProp("redirect.sso.provider",
			"/simplesaml/tangramportal.php");
	public static final String SSO_PROVIDER_URL1 = Utils.readProp("redirect.sso.provider1",
			"/simplesaml/tangramportal.php");
	public static final String SSO_PROVIDER_URL2 = Utils.readProp("redirect.sso.provider2",
			"/simplesaml/tangramportal.php");
	public static final String SSO_PROVIDER_URL3 = Utils.readProp("redirect.sso.provider3",
			"/simplesaml/tangramportal.php");
	public static final String SSO_PROVIDER_URL4 = Utils.readProp("redirect.sso.provider4",
			"/simplesaml/tangramportal.php");
	private static final String SSO_SHARED_SECRET = Utils.readProp("redirect.sso.shared_secret", "change_asap");
	private static final int SSO_ALLOWED_CLOCK_SKEW = Integer.parseInt(Utils.readProp("redirect.sso.allowed_clock_skew", "600"));
	private static final String CERT_AUTH_LEVEL_VAR = Utils.readProp("cert.auth.level.var", "auth_level");
	private static final String CERT_AUTH_LEVEL_VALUE =  Utils.readProp("cert.auth.level.value", "2");
	private static final String TANGRAM_LAST_LOGIN_URL = Utils.readProp("auth.last_login_url", "http://tangramdt:12080/ajax/get-last-connection/?identifier=%s");
	private static final String LAST_CONNECTED_SESSION_VARIABLE = Utils.readProp("auth.last_connected.sessionvariable", "USER_LAST_CONNECTED");
	private Map<String, String> auth_info_map = new HashMap<String, String>();
	private Map<String, String> auth_info_map2 = new HashMap<String, String>();
	private static final int AUTH_INFO_MAX = 20;
	public static String user_id_sessionvariable = null;


	public AuthenticationAction() {
		// Read variable map, The first sessionvariable is the user id.
		for (int i=1; i <= AUTH_INFO_MAX; i++) {
			String prop = "auth.info" + i;
			String outputvariable = Utils.readPropSilent(prop + ".outputvariable", "");
			String outputvariable2 = Utils.readPropSilent(prop + ".outputvariable2", "");
			String sessionvariable = Utils.readPropSilent(prop + ".sessionvariable", "");
			if (sessionvariable != null) {
				if (user_id_sessionvariable == null) {
					user_id_sessionvariable = new String(sessionvariable);
				}
				if (outputvariable != null)
					auth_info_map.put(sessionvariable, outputvariable);
				if (outputvariable2 != null) {
					auth_info_map2.put(sessionvariable, outputvariable2);
				}
			}
		}
	}


	public String execute(HttpServletRequest request, HttpServletResponse response)
	throws Exception {
		HttpSession session = Utils.getSession(request);
		String returnTo = (String) session.getAttribute("redirect");
		log.debug("Struts action session id: " + session.getId());
		if (request.getPathInfo().contains("cert-login"))
			cert(request, response, returnTo);
		else if (request.getPathInfo().contains("sso-login"))
			sso(request, response, returnTo);
		else
			sendError("unknow-auth-method", request, response);
		return null;
	}

	public static String getAuthenticationSource(HttpServletRequest request) {
		String result = null;
		String required_auth_level = request.getParameter(CERT_AUTH_LEVEL_VAR);
		if (required_auth_level != null) {
			if (required_auth_level.equals("2") || required_auth_level.equals("cert"))
				result = "cert";
			if (required_auth_level.equals("sso"))
				result = "sso";
		}
		return result;
	}



	public void sso(HttpServletRequest request, HttpServletResponse response, String returnTo) throws IOException, ServletException {
		String authToken = request.getParameter("auth");
		String url = "/";
		String error = null;
		if (authToken == null) {
			url = SSO_PROVIDER_URL;
			String as = request.getParameter("as");
			if ("1".equals(as))
				url = SSO_PROVIDER_URL1;
			else if ("2".equals(as))
				url = SSO_PROVIDER_URL2;
			else if ("3".equals(as))
				url = SSO_PROVIDER_URL3;
			else if ("4".equals(as))
				url = SSO_PROVIDER_URL4;
			if (url == null || url.isEmpty())
				url = SSO_PROVIDER_URL;
		}
		else {
			// This is a SSO request
			String uid = null;
			String timestamp = request.getParameter("timestamp");
			if (timestamp == null){
				error = "sso-no-timestamp-provided";
			}
			if (error == null) {
				uid = request.getParameter("uid");
				if (uid == null){
					error = "sso-no-uid-provided";
				}
			}
			if (error == null) {
				// check if timestamp is near enough
				int ts = 0;
				try {
					ts = Integer.parseInt(timestamp);
					if (Math.abs(ts - System.currentTimeMillis() / 1000) > SSO_ALLOWED_CLOCK_SKEW){
						error = "sso-timestamp-too-far";
					}
				}
				catch (java.lang.NumberFormatException exc){
					error = "sso-invalid-timestamp";
				}
			}
			if (error == null) {
				// check auth token
				String data = timestamp + uid + SSO_SHARED_SECRET;
				String mac = sha1(data);
				if (! mac.equals(authToken)){
					error = "sso-auth-token-mismatch";
				}
			}
			if (error == null) {
				// copy attributes to session variables
				// TODO: refactor with certificate auth
				log.info("User '" + uid + "' authenticated for protected pages.");
				HttpSession session = Utils.getSession(request);
				for (Map.Entry<String,String> me: auth_info_map2.entrySet())
				{
					String value = request.getParameter(me.getValue());
					if (value != null)
						session.setAttribute(me.getKey(), value);
				}
				if (returnTo != null && !returnTo.isEmpty()){
					session.setAttribute("redirect", null);
					url = returnTo;
				}
				// Store auth level for SSO
				session.setAttribute(CERT_AUTH_LEVEL_VAR, "1");
			}
		}
		if (error != null) {
			sendError(error, request, response);
			return;
		}
		setLastLoginInSession(request);
		log.debug("Redirect to: " + url);
		Utils.redirect(url, response);
	}

	public static void sendError(String error, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		ThemeDisplay td = (ThemeDisplay) request.getAttribute(WebKeys.THEME_DISPLAY);
		error = td.translate(error);
		PortalUtil.sendError(new TransformException(error), request, response);

	}

	public static String byteArrayToHexString(byte[] b) {
		String result = "";
		for (int i=0; i < b.length; i++) {
			result += Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
		}
		return result;
	}


	public static String sha1(String data) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		}
		catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			data = byteArrayToHexString(md.digest(data.getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
		return data;
	}

	public void cert(HttpServletRequest request, HttpServletResponse response, String returnTo) throws IOException, ServletException {
		HttpSession session = Utils.getSession(request);
		String url = "/";
		if (checkCertificate(request, response)){
			if (returnTo != null && !returnTo.isEmpty()){
				session.setAttribute("redirect", null);
				url = returnTo;
			}
			setLastLoginInSession(request);
			log.debug("Redirect to: " + url);
			Utils.redirect(url, response);
		}
	}

	public boolean checkCertificate(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		// Returns true if certificate is valid, else false.
		String HTTP_HEADER_AUTHDATA = Utils.readProp("http.header.authdata", "ssl_client_cert");
		HttpSession session = Utils.getSession(request);
		String auth_info = request.getHeader(HTTP_HEADER_AUTHDATA);
		// We get certificate from header which is multiline, remove any whitespaces and tabs
		auth_info = auth_info.replace("\t", "");
		String error = null;
		String[] resp=null;
		log.debug("Header is: " + auth_info);
		if (auth_info == null)
		{
			log.warn("No certificate in header!");
			error = "Error en la autenticación. Contacte el administrador.";
		}
		if (error == null) {
			log.debug("Certificate in header");
			resp = getAuthInfo(auth_info);
			if (resp[0] == "ERROR")
			{
				log.error("Error when checking certificate");
				error = "Error al comprobar el certificado. Pruebe más tarde.";
			}
			else if (resp[0] == "OK") {
				// certinfo should be OK, now parse the data
				log.info("Cert authentication successfull.");
				session.setAttribute(CERT_AUTH_LEVEL_VAR, CERT_AUTH_LEVEL_VALUE);
				Map <String, String> out_map = new HashMap<String, String>();
				for (String line: resp[1].split("[\n\r]")) {
					if (! line.trim().equals("")) {
						String[] outprop = line.trim().split("[=]", 2);
						if (outprop.length > 1)
							out_map.put(outprop[0], outprop[1]);
					}
				}
				for (Map.Entry<String,String> me: auth_info_map.entrySet())
				{
					String key = me.getKey();
					String value = out_map.get(me.getValue());
					log.info("Session attribute: " + key + " = " + value);
					session.setAttribute(key, value);
				}
			}
			else {
				log.warn("Invalid certificate.");
				error = "El certificado no es válido (caducado o revocado)."; // check restricted URLs
				}
		}
		if (error != null) {
			sendError(error, request, response);
			return false; // check for restricted URLs
		}
		return true;
	}

	public void setLastLoginInSession(HttpServletRequest request) {

		HttpSession session = Utils.getSession(request);

		String result = "";
		String url = "";

		try {
			String uid = (String) session.getAttribute(user_id_sessionvariable);
			url = String.format(TANGRAM_LAST_LOGIN_URL, uid);
			log.info("Trying to get last login for user: " + url);
			HttpURLConnection connection = (HttpURLConnection) (new URL(url)).openConnection();

			//add reuqest header
			connection.setRequestMethod("GET");
			connection.setRequestProperty("User-Agent", "Java HttpURLConnection: Tgauth-hook");

			int rc = connection.getResponseCode();

			if (rc == 200){
				InputStream inputStream = connection.getInputStream();
				try {
					result = IOUtils.toString(inputStream, "UTF-8");
				} finally {
					IOUtils.closeQuietly(inputStream);
				}
				log.info("Got last login for user " + uid +": " + result);
			} else {
				log.warn("Response code: " + rc);
			}
		} catch (Exception exc) {
			log.error("Getting last login from " + url + ": " + exc.getMessage(), exc);
			result = "";
		}

		try{
			log.info("Session attribute: " + LAST_CONNECTED_SESSION_VARIABLE + " = " + result);
			session.setAttribute(LAST_CONNECTED_SESSION_VARIABLE, result);
		} catch (Exception e)  {
			String msg = "Error when saving last connection in Session: " + e.toString();
			log.error(msg);
		}

	}


	public void copyAttributes(String text, HttpSession session, Map<String, String> auth_info_map) {
		// certinfo should be OK, now parse the data
		Map <String, String> out_map = new HashMap<String, String>();
		for (String line: text.split("[\n\r]")) {
			if (! line.trim().equals("")) {
				String[] outprop = line.trim().split("[=]", 2);
				if (outprop.length > 1)
					out_map.put(outprop[0], outprop[1]);
			}
		}
		for (Map.Entry<String,String> me: auth_info_map.entrySet())
		{
			session.setAttribute(me.getKey(), out_map.get(me.getValue()));
		}

	}

	class CmdResult{
		public String result;
		public int status;
		CmdResult (String result, int status) {
			this.result = result;
			this.status = status;
		}
	}

	// execute external command to check certificate
	// returns [status, auth_string], where status == "OK", if valid, auth_string == info
	public String[] getAuthInfo(String cert)
	{
		String rv[] = new String[2];
		CmdResult result;
		rv[0] = "FAIL";
		try {
			if (CMD.startsWith("http:") || CMD.startsWith("https:")) {
				log.info("Using URL to validate certificate: " + CMD);
				result = plainTextWSRequest(CMD, cert);
			}
			else {
				log.info("Running certcheck command: " + CMD);
				result = runCommand(CMD, cert);
			}
			log.debug("Command output is: " + result);
			if (result.status != 0) {
				rv[0] = "ERROR";
				log.error("Error, check command exited with: " + result.status);
			}
			else
			{
				// Check certificate status
				rv[0] = "OK";
				rv[1] = result.result;
			}
		} catch (Exception e) {
			String msg = "Error when calling command: " + e.toString();
			log.error(msg);
			rv[0] = "ERROR";
			rv[1] = msg;
		}
		return rv;
	}


	/**
	 * Invoke simple WS to validate certificate.
	 *
	 * We receive an plain text result in the form of key=value lines.
	 *
	 * @param url The WS url
	 * @param certificate The certificate in PEM format
	 * @return Plain text response text key=value lines
	 */
	protected CmdResult plainTextWSRequest(String url, String certificate) {
		String result = "";
		try {
			URL obj = new URL(url);
			HttpURLConnection connection = null;
			connection = (HttpURLConnection) obj.openConnection();

			//add reuqest header
			connection.setRequestMethod("POST");
			connection.setRequestProperty("User-Agent", "Java HttpURLConnection: Tgauth-hook");
			StringBuilder data = new StringBuilder("certificate=" + URLEncoder.encode(certificate, "UTF-8"));

			// Send post request as URL
			connection.setDoOutput(true);
			PrintWriter out = new PrintWriter(connection.getOutputStream());
			out.println(data);
			out.close();

			int rc = connection.getResponseCode();
			System.out.println("\nSending 'POST' to URL : " + url);
			System.out.println("Response code: " + rc);

			InputStream inputStream = connection.getInputStream();
			try {
				result = IOUtils.toString(inputStream, "UTF-8");
			} finally {
				IOUtils.closeQuietly(inputStream);
			}
		} catch (Exception exc) {
			result = "status=error\nmessage=" + exc.toString() + "\n";
		}
		return new CmdResult(result, result.contains("status=success") ? 0 : 1);
	}

	/**
	 * Invoke command line validator to validate certificate.
	 *
	 * We receive an plain text result in the form of key=value lines.
	 *
	 * @param cmd The command use to validate the certificate
	 * @param certificate The certificate in PEM format
	 * @return Plain text response text key=value lines
	 */
	protected CmdResult runCommand(String cmd, String certificate) throws IOException, InterruptedException {
		String result = "";
		int status = 0;
		try {
			Runtime rt = Runtime.getRuntime();
			Process pr = rt.exec(cmd);
			// write cert data to stdout (for input to the command)
			OutputStream stdin = pr.getOutputStream(); stdin.write(certificate.getBytes()); stdin.close();
			// get result
			InputStream inputStream = pr.getInputStream();
			try {
				result = IOUtils.toString(inputStream, "UTF-8");
				status = pr.waitFor();
			} finally {
				IOUtils.closeQuietly(inputStream);
			}
		} catch (Exception exc) {
			result = "status=error\nmessage=" + exc.toString() + "\n";
		}
		return new CmdResult(result, status);
	}
}
