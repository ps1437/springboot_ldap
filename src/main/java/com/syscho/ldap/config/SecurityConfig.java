package com.syscho.ldap.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Praveen $oni
 * @category Security Config with Ldap
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${ldap.url}")
	private String ldapUrl;
	@Value("${ldap.base.dn}")
	private String baseDn;
	@Value("${ldap.user.dn.pattern}")
	private String ldapUserDnPattern;
	@Value("${ldap.searchbase}")
	private String ldapSearchBase;

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public AuthenticationManager customAuthenticationManager() throws Exception {
		return authenticationManager();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.ldapAuthentication().userDnPatterns(ldapUserDnPattern).groupSearchBase(ldapSearchBase).contextSource()
				.url(ldapUrl).and().passwordCompare().passwordEncoder(new BCryptPasswordEncoder())
				.passwordAttribute("userPassword");
	}

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/auth/**", "/swagger-resources/**", "/api**", "/swagger-ui.html", "/resources/**");

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().disable();
		http.httpBasic();
		http.authorizeRequests().antMatchers("/*").authenticated();
	}

}
