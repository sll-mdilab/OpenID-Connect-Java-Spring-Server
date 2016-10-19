package net.sllmdilab.openid.authentication;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class DefaultSithsAuthenticationProvider implements AuthenticationProvider {

	private static final String SERIALNUMBER_PATTERN = "SERIALNUMBER=(.*?)(?:,|$)";
	private Pattern serialNumberPattern = Pattern.compile(SERIALNUMBER_PATTERN, Pattern.CASE_INSENSITIVE);

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		final Object credentials = authentication.getCredentials();

		if (!(credentials instanceof X509Certificate)) {
			return null;
		}

		String username = extractSerialNumber(credentials);

		UserDetails userDetails = new User(username, "", Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

		return new PreAuthenticatedAuthenticationToken(userDetails, authentication.getCredentials(),
				userDetails.getAuthorities());
	}

	private String extractSerialNumber(final Object credentials) {
		Matcher matcher = serialNumberPattern.matcher(credentials.toString());

		if (!matcher.find()) {
			throw new BadCredentialsException(String.format("SERIALNUMBER not found in subject DN: {0}", credentials));
		}
		return matcher.group(1);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
