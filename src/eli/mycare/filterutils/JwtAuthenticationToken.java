package eli.mycare.filterutils;

import java.util.Collection;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
	final static Logger logger = Logger.getLogger(JwtAuthenticationToken.class);
	private static final long serialVersionUID = 1L;
	private Object principal;
	private Object credentials;
	private String token;

	public JwtAuthenticationToken(String token) {
		//super(AuthorityUtils.createAuthorityList("Administrator"));
		super(null);
		this.token = token;
		setAuthenticated(false);
	}

	public JwtAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

	public String getToken() {
		return token;
	}
	
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		}
		super.setAuthenticated(false);
	}
}