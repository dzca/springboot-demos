package com.elk.security.config;

import com.elk.security.component.CustomTokenAuthenticationProvider;
import com.elk.security.filter.CustomTokenFilter;
import com.elk.security.filter.LoggingFilter;
import jakarta.servlet.Filter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
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
				.httpBasic(Customizer.withDefaults()) //No Http Basic Login
				.csrf(c -> c.disable()) //No CSRF token
				.formLogin(Customizer.withDefaults());
//				.formLogin(c -> c.loginPage("/signin")
//						.usernameParameter("email")
//						.defaultSuccessUrl("/api/user/1", true)
//						.permitAll())
//				.logout(c -> c.disable())
//				.sessionManagement( c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//				//.authenticationProvider(customTokenAuthenticationProvider)
//				.addFilterBefore(getFilter(httpSecurity), AnonymousAuthenticationFilter.class);

		//httpSecurity.addFilterAfter(loggingFilter, BasicAuthenticationFilter.class);
		return httpSecurity.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	/**
	 * From Spring Security 6.3 version
	 *
	 * @return
	 */
	@Bean
	public CompromisedPasswordChecker compromisedPasswordChecker() {
		return new HaveIBeenPwnedRestApiPasswordChecker();
	}
}
