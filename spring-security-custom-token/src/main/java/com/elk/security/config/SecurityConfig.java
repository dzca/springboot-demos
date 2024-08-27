package com.elk.security.config;

import com.elk.security.component.CustomTokenAuthenticationProvider;
import com.elk.security.filter.CustomTokenFilter;
import com.elk.security.filter.LoggingFilter;
import jakarta.servlet.Filter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@AllArgsConstructor
@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {

	LoggingFilter loggingFilter;
	CustomTokenAuthenticationProvider customTokenAuthenticationProvider;

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.authorizeHttpRequests(r-> r.requestMatchers("/public/**").permitAll()
						// .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
						.anyRequest().authenticated()
				)
				.httpBasic(b -> b.disable()) //No Http Basic Login
				.csrf(c -> c.disable()) //No CSRF token
				.formLogin(f -> f.disable())
				.logout(c -> c.disable())
				.sessionManagement( c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				//.authenticationProvider(customTokenAuthenticationProvider)
				.addFilterBefore(getFilter(httpSecurity), AnonymousAuthenticationFilter.class);

		//httpSecurity.addFilterAfter(loggingFilter, BasicAuthenticationFilter.class);
		return httpSecurity.build();
	}


	@Bean
	public AuthenticationManager authManager(HttpSecurity http) throws Exception {
		AuthenticationManagerBuilder authenticationManagerBuilder =
				http.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder.authenticationProvider(customTokenAuthenticationProvider);
		return authenticationManagerBuilder.build();
	}

	private Filter getFilter(HttpSecurity http) throws Exception {
		return new CustomTokenFilter(getRequestMatchers(), authManager(http));
	}

	private RequestMatcher getRequestMatchers() {
		return new OrRequestMatcher(new AntPathRequestMatcher("/api/**"));
	}
}
