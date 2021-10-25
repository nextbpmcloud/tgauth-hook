package es.tangrambpm.liferay;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.HttpUtil;
import com.liferay.portal.util.PortalUtil;

/**
 * Servlet Filter implementation class AuthenticationFilter
 */
public class AuthenticationFilter implements Filter {
    private static Log log = LogFactoryUtil.getLog(AuthenticationFilter.class);
    private static final Pattern RESTRICTED_PATH_REGEX = regex_helper(Utils.readProp("restricted_path_regex"));    
    private static final String REDIRECT_LOGIN = Utils.readProp("redirect.login", "/tgauth/login");
    private static final String REDIRECT_LOGIN_CERT = Utils.readProp("redirect.login.cert", "/c/portal/cert-login");
	private static final String REDIRECT_LOGIN_SSO = Utils.readProp("redirect.login.sso", "/c/portal/sso-login");

    /**
     * @see Filter#init(FilterConfig)
     */
    // Read auth properties Map of variables
    public void init(FilterConfig fConfig) throws ServletException {
    }


    // Return a Pattern object if string not null or empty
    public static Pattern regex_helper(String pattern)
    {
        if (pattern == null || pattern.equals(""))
            return null;
        return Pattern.compile(pattern);
    }

    
    /**
     * @see Filter#destroy()
     */
    public void destroy() {
    }

    /**
     * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    	if (isProtected(request)){
    		// legacy
			String auth_source = AuthenticationAction.getAuthenticationSource((HttpServletRequest) request);
			if (!alreadyChecked(request) || auth_source != null) {
				redirectToLogin(request, response, auth_source);
    			return;
    		}
    	}
        chain.doFilter(request, response);
    }

    public boolean isProtected(ServletRequest request){
        if (RESTRICTED_PATH_REGEX == null)
            return true;
        String path = PortalUtil.getCurrentURL((HttpServletRequest) request);
        log.debug("Checking path: " + path);
        if (RESTRICTED_PATH_REGEX.matcher(path).matches()){
            log.debug("This path is restricted.");
        	return true;
        }
        return false;
    }

    
    public boolean alreadyChecked(ServletRequest request){
        HttpSession session = Utils.getSession(request);
        log.debug("Filter session id: " + session.getId());
        String user = (String) session.getAttribute(AuthenticationAction.user_id_sessionvariable);
        if (user == null || user.isEmpty())
        {
        	log.debug("User not checked.");
            return false;
        }
    	log.debug("User already checked: " + user);
        return true;
    }
    
	public void redirectToLogin(ServletRequest request, ServletResponse response, String auth_source)
    {
    	log.debug("User not checked. Redirecting...");
		String redirectUrl = REDIRECT_LOGIN;
		String as = null;
		if (auth_source != null) {
			if (auth_source.equals("cert"))
				redirectUrl = REDIRECT_LOGIN_CERT;
			else if (auth_source.equals("sso")) {
				redirectUrl = REDIRECT_LOGIN_SSO;
				as = request.getParameter("as");
			}
		}
        String currentURL = PortalUtil.getCurrentURL((HttpServletRequest) request);
		currentURL = HttpUtil.removeParameter(currentURL, "auth_level");
		currentURL = HttpUtil.removeParameter(currentURL, "as");
        redirectUrl = HttpUtil.addParameter(redirectUrl, "redirect", currentURL);
		if (as != null)
			redirectUrl = HttpUtil.addParameter(redirectUrl, "as", as);
        HttpSession session = Utils.getSession(request);
        session.setAttribute("redirect", currentURL);
		Utils.redirect(redirectUrl, (HttpServletResponse) response);
    }
}
