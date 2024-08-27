package com.elk.security.filter;

import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class CustomTokenFilter extends AbstractAuthenticationProcessingFilter {

	public CustomTokenFilter(RequestMatcher requiresAuthenticationRequestMatcher,
							 AuthenticationManager authenticationManager) {
		super(requiresAuthenticationRequestMatcher);
		//Set authentication manager
		setAuthenticationManager(authenticationManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		// Extract from request
		String header = request.getHeader("X-Auth");
		// Create a token object ot pass to Authentication Provider
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(header, null);
		return getAuthenticationManager().authenticate(token);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
											Authentication authResult) throws IOException, ServletException {
		// Save user principle in security context
		SecurityContextHolder.getContext().setAuthentication(authResult);
		chain.doFilter(request, response);
	}

}

