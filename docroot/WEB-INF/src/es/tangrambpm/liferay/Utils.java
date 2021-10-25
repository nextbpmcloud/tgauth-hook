package es.tangrambpm.liferay;
import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.servlet.SessionErrors;
import com.liferay.portal.kernel.util.HttpUtil;
import com.liferay.util.portlet.PortletProps;


public class Utils {
    private static Log log = LogFactoryUtil.getLog(Utils.class);
    private static final String REDIRECT_ERROR = Utils.readProp("redirect.error", "/tgauth/error");


	// Read property from properties file, don't warn if not set
	public static String readPropSilent(String name, String defaultValue)
	{
	    return _readProp(name, defaultValue, false);
	}
	
	// Read property from properties file, log, warn if not set.
	public static String readProp(String name, String defaultValue)
	{
	    return _readProp(name, defaultValue, true);
	}
	
	// Read property from properties file, log, warn if not set.
	public static String _readProp(String name, String defaultValue, boolean show_warnings)
	{
	    String value = PortletProps.get(name);
	    if (value == null)
	    {
	        if (show_warnings)
	            log.warn(name + " property not set. Using default: " + defaultValue);
	        value = defaultValue;
	    }
	    log.info("  " + name + " = " + value);
	    return value;
	}
	
	// Read property with default value null
	public static String readProp(String name)
	{
	    return readProp(name, null);
	}
	
    // redirect to URL if possible and return false.
    public static boolean redirect(String url, HttpServletResponse response)
    {
        try
        {
            response.sendRedirect(url);
            return true;
        }
        catch (IOException e)
        {
            log.error("Cant redirect!");
        }
        return false; // whenever we do redirects, we don't need further checks
    }
    public static boolean showError(String errorMessage, HttpServletRequest request, HttpServletResponse response){
    	String url = REDIRECT_ERROR;
        url = HttpUtil.addParameter(url, "error", errorMessage);
        SessionErrors.add(request, errorMessage);
    	return redirect(url, response);
    }
    
    public static HttpSession getSession(ServletRequest request) {
        return ((HttpServletRequest) request).getSession();
    }
}
