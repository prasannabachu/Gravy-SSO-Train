package eli.mycare.filterutils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.Properties;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.JSONObject;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.log4j.Logger;


public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	final static Logger logger = Logger.getLogger(JwtAuthenticationFilter.class);
	public String pairKey = getpairkey();
	
	public String getpairkey() {
		Properties prop = new Properties();
		InputStream input = null;
		try {
			//System.out.println("newfile place"+  new File(".").getAbsolutePath());
		    input = new FileInputStream("jwt.properties");
		    prop.load(input);
		    pairKey = prop.getProperty("pairKey");
		    //System.out.println("pairKey-----=---------"+ pairKey);
		    logger.debug("pairKey===> " + pairKey);
		} catch (IOException ex) {
		    ex.printStackTrace();
		}
		return pairKey;
	}
	
	
    public JwtAuthenticationFilter() {
        //super("/**");
    	//super(new AntPathRequestMatcher("/**"));
		super(new AntPathRequestMatcher("/login/**"));
    }

    
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) throws SecurityException{
    	if (request.getParameter("Token") != null){
    		if (SecurityContextHolder.getContext().getAuthentication() == null || !SecurityContextHolder.getContext().getAuthentication().isAuthenticated()){
    			return true;
    		}
    		else {
    			return false;
    		}
    	}
    	else{
    		return false;
    	}
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    	//clearAuthenticationAttributes(request);
        //String header = request.getHeader("Authorization");
        String requestParam = request.getParameter("Token");
             
        System.out.println("tokenValue---->"+requestParam );
        logger.debug("tokenValue===> " + requestParam);
        /*if (header == null || !header.startsWith("Bearer ")) {
            throw new AuthenticationCredentialsNotFoundException("No JWT token found in request headers");
        }*/
        
        String authToken = requestParam;
        String name="";
        try {
          	name = parseAndVerifyToken(authToken, pairKey);
        }catch (Exception e) {
			// TODO: handle exception
        	e.printStackTrace();
		}
        if (name == null) {
            throw new AuthenticationCredentialsNotFoundException("No JWT token found in request headers");
        }
        if(name.trim().length() <= 0) {
        	throw new AuthenticationCredentialsNotFoundException("Invalid JWT token found in request headers");
        }
        System.out.println(name+"------authToken");
        logger.debug("------authToken===> " + name);
        JwtAuthenticationToken authRequest = new JwtAuthenticationToken(name);
        // Allow subclasses to set the "details" property
 		setDetails(request, authRequest);
 		
        return getAuthenticationManager().authenticate(authRequest);
    }
    
    
    public String parseAndVerifyToken(String jwtString, String pairKey) throws Exception {
    	SignedJWT signedJWT = SignedJWT.parse(jwtString);
    	System.out.println("JWTToken======="+signedJWT);
     	boolean check = false;
      	long parsedDateTime = 0;
      	long todayTimeInSeconds ;
		String sample;
    	try {
 				JWSVerifier verifier = new RSASSAVerifier(getRSAPublicKey(pairKey));
				check = signedJWT.verify(verifier);
				
				//System.out.println("todayTimeInSeconds----->" + todayTimeInSeconds);
  				//todayTimeInSeconds =new Date();
				//System.out.println("DateTIme===="+todayTimeInSeconds);
				
				
    	    }
    	    catch (JOSEException e) {
    	      System.err.println("Couldn't verify signature: " + e.getMessage());
    	    }
    	
    	if (check){
     		JSONObject jsonObj1 = new JSONObject(signedJWT.getJWTClaimsSet().getCustomClaim(("user_metadata")).toString());
    		JSONObject jsonObj12 = new JSONObject(signedJWT.getJWTClaimsSet().getAllClaims());
    				//getCustomClaim(("allClaims")).toString());
    		
    		System.out.println("jsonobject 2====="+jsonObj12 );
    		
    		 sample =  jsonObj12.get("exp").toString();
    		System.out.println("sample====="+sample);
    		DateFormat formatter = new SimpleDateFormat("E MMM dd HH:mm:ss Z yyyy");
    		Date date = (Date)formatter.parse(sample);
    		//SimpleDateFormat formatter5=new SimpleDateFormat("E, MMM dd yyyy HH:mm:ss");
    		//Date date5=formatter5.format(sample);
    		//System.out.println("DateFormatter===="+date5);
    		//parsedDateTime =  Long.parseLong(sample);
    		//System.out.println("final time ====="+parsedDateTime);
    		parsedDateTime=date.getTime() / 1000;
    		todayTimeInSeconds = new Date().getTime() / 1000;
    		System.out.println("DateTIme===="+todayTimeInSeconds);
//    		if(date.after(new Date())) {
    		if(parsedDateTime>=todayTimeInSeconds) {
    			return jsonObj1.get("Username").toString();
    		}else {
    			return null;
    		}
    	}
    	else{
    		return null;
    	}
    }
    
    public static RSAPublicKey getRSAPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	byte[] decoded = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey generatePublic = (RSAPublicKey) kf.generatePublic(spec);
        return generatePublic;
    }
  
   
    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request, JwtAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
    	SecurityContextHolder.getContext().setAuthentication(authResult);
        // As this authentication is in HTTP header, after success we need to continue the request normally
        // and return the response as if the resource was not secured at all
        //chain.doFilter(request, response);
    	//handle(request, response, authResult);
		clearAuthenticationAttributes(request);
		//response.sendRedirect(request.getContextPath()+"/dist/#/login");
		//response.sendRedirect("http://10.93.27.39:8081/dist/#/dashboard");
    }

	/**
	 * Removes temporary authentication-related data which may have been stored in the
	 * session during the authentication process.
	 */
	protected final void clearAuthenticationAttributes(HttpServletRequest request) throws ServletException{
		HttpSession session = request.getSession(false);
		if (session == null) {
			return;
		}
		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}
}
