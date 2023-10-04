package com.Flight1.config;


import java.io.IOException;
import java.nio.file.AccessDeniedException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.Flight1.service.UserinfoUserDeatailsService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	//public CustomerServiceimp Customerserviceimp;
	
	@Bean
	public UserDetailsService userDetailsService(){
		return new UserinfoUserDeatailsService();
	}

    @Bean
   public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationProvider authenticatonProvider() {
		DaoAuthenticationProvider daoAauthenticationProvider = new DaoAuthenticationProvider();
				daoAauthenticationProvider.setUserDetailsService(userDetailsService());
		daoAauthenticationProvider.setPasswordEncoder(passwordEncoder());
		return daoAauthenticationProvider;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticatonProvider());
	}
	
	

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    http.authorizeRequests()
	        .antMatchers("/v2/register").permitAll()
	        .antMatchers("/forgot-password").permitAll()
	        .antMatchers("/reset-password").permitAll()
	        
	        .antMatchers("/v2/registration-success").permitAll()
	        .antMatchers("/login", "/css/**", "/js/**").permitAll()
	        .antMatchers("/v1/**").hasAuthority("ADMIN")
	        .antMatchers("/v2/**").hasAuthority("CUSTOMER")
	        .anyRequest().authenticated()
	        .and()
	        .formLogin()
	            .loginPage("/login")
	            .defaultSuccessUrl("/dashboard", true)
	            .permitAll()
	        .and()
	        .logout()
	            .logoutSuccessUrl("/login")
	            .invalidateHttpSession(true)
	            .deleteCookies("JSESSIONID")
	        .and()
	        .csrf()
	            .ignoringAntMatchers("/v2/register") // Ignore CSRF protection for "/v2/register" URL
	            .ignoringAntMatchers("/v1/flight")
	            .ignoringAntMatchers("/v1/update")
	            .ignoringAntMatchers("/book-flight")
	    .ignoringAntMatchers("/v1/delete");
	    
	}

	



	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		return new CustomAccessDeniedHandler();
	}
	
	
	public class CustomAccessDeniedHandler implements AccessDeniedHandler {
		public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
			// Custom logic for handling access denied
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
		}

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response,
				org.springframework.security.access.AccessDeniedException accessDeniedException)
				throws IOException, ServletException {
			// TODO Auto-generated method stub
			
		}
	}


	
	

}
