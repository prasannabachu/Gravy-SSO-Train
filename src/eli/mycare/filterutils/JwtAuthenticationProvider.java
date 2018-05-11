package eli.mycare.filterutils;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;


public class JwtAuthenticationProvider implements AuthenticationProvider {
	final static Logger logger = Logger.getLogger(JwtAuthenticationProvider.class);
	private UserDetailsService userDetailsService;
	
	public JwtAuthenticationProvider(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}
	
    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    	//return true;AnonymousAuthenticationProvider
    }

    @Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    	System.out.println("in authenticate..");
    	JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
    	if (jwtAuthenticationToken.isAuthenticated())
    	{
    		return jwtAuthenticationToken;
    	}
        String tokenString = jwtAuthenticationToken.getToken();

        JWTToken token = new JWTToken();
        //u.setUsername(body.getSubject());
        token.setUsername(tokenString);
        //u.setId(Long.parseLong((String) body.get("userId")));
        //u.setRole((String) body.get("role"));
    	token.setRole("Administrator");
        
        if (token == null) {
        	throw new AuthenticationCredentialsNotFoundException("JWT token is not valid");
        }
    	
        UserDetails loadedUser = getUserDetails(token.getUsername());
        validateUser(loadedUser);
        //return new AuthenticatedUser(parsedUser.getId(), parsedUser.getUsername(), token, authorityList);
        return createSuccessAuthentication(loadedUser, jwtAuthenticationToken, loadedUser);
    }
    
    
    
	private void validateUser(UserDetails loadedUser) {
		if (!loadedUser.isAccountNonExpired() || !loadedUser.isAccountNonLocked() || !loadedUser.isEnabled())
		{
			throw new InternalAuthenticationServiceException(
				"UserDetailsService returned null, which is an interface contract violation");
		}
	}

	private UserDetails getUserDetails(String username) {
		UserDetails loadedUser;
		try {
			loadedUser = this.getUserDetailsService().loadUserByUsername(username);
		}
		catch (UsernameNotFoundException notFound) {
			// Redirect to login page if required.
			throw notFound;
		}
		catch (Exception repositoryProblem) {
			throw new InternalAuthenticationServiceException(
					repositoryProblem.getMessage(), repositoryProblem);
		}
		if (loadedUser == null) {
			throw new InternalAuthenticationServiceException(
					"UserDetailsService returned null, which is an interface contract violation");
		}
		return loadedUser;
	}
	
	protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
		// Ensure we return the original credentials the user supplied,
		// so subsequent attempts are successful even with encoded passwords.
		// Also ensure we return the original getDetails(), so that future
		// authentication events after cache expiry contain the details
		JwtAuthenticationToken result = new JwtAuthenticationToken(principal, authentication.getCredentials(), user.getAuthorities());
		result.setDetails(authentication.getDetails());
		return result;
	}
	
	private UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

}