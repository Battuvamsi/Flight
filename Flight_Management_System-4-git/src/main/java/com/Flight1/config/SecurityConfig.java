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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.Flight1.service.CustomerServiceimp;
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
	
//	@Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http
//        		 .antMatcher("/v1/**")
//        	     .authorizeRequests()
//        	         .antMatchers("/v1/test").hasRole("ADMIN")
//        	         .antMatchers("/v1/flight").hasRole("ADMIN")
//        	         .and()
////            .authorizeRequests()
////                .antMatchers("/v1/**").hasRole("ADMIN")
////                .antMatchers("/v2/**").hasRole("CUSTOMER")
////                .anyRequest().authenticated()
////                .and()
//            .formLogin()
//                .and()
//            .httpBasic()
//                .and()
//            .csrf().disable()
//            .build();
//    }
//	
//	
//	@Bean
//    public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
//        return http
//        		 .antMatcher("/v2/**")
//        	     .authorizeRequests()
//        	         .antMatchers("/v2/register").hasRole("ADMIN")
//        	         .antMatchers("/v1/").hasRole("ADMIN")
//        	         .and()
////            .authorizeRequests()
////                .antMatchers("/v1/**").hasRole("ADMIN")
////                .antMatchers("/v2/**").hasRole("CUSTOMER")
////                .anyRequest().authenticated()
////                .and()
//            .formLogin()
//                .and()
//            .httpBasic()
//                .and()
//            .csrf().disable()
//            .build();
//    }
//	
	
	
	
	
//	 .antMatcher("/admin/**")
//     .authorizeRequests()
//         .antMatchers("/admin/dashboard").hasRole("ADMIN")
//         .antMatchers("/admin/users").hasRole("ADMIN")
//         .and()
	
//	@Bean
//  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		http
//	
//	.authorizeRequests()
//    .antMatchers("/v1/**").hasRole("ADMIN") 
//    .antMatchers("/v2/**").hasRole("CUSTOMER") 
//    .anyRequest().authenticated()
//    .and()
//.formLogin()
//    .and()
//.logout();
//		  return http.build();
//	}
          

	
//	@Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		return http.csrf().disable()
//				.authorizeHttpRequests()
//				.antMatchers("/v2/delete/{id}")
//				.permitAll()
//				.and()
//				.authorizeHttpRequests()
//				.antMatchers("/v2/**")
//				.authenticated()
//				.antMatchers("/v1/**")
//				.authenticated()
//				.and()
//			
//				.formLogin().and()
//				.build();
//				
//		
//	}
	
//       @Override
//	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//	        auth.authenticationProvider(authenticatonProvider());
//	    }
//	
//	
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//            .antMatchers("/v1/**").hasAnyAuthority( "ADMIN")
//            .antMatchers("/v2/**").hasAnyAuthority("CUSTOMER")
//            .anyRequest().authenticated()
//            .and()
//            .formLogin().permitAll()
//            .and()
//            .logout().permitAll()
//            .and()
//            .exceptionHandling().accessDeniedPage("/403")
//            ;
//	}
           
//           @Bean
//           public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//               http.csrf().disable()
//                   .authorizeRequests()
//                       .antMatchers("/v2/register").permitAll() // Allow access to "/v1/register" without authentication
//                       .antMatchers("/v2/**").authenticated()
//                      .antMatchers("/v1/**").authenticated()  
//                      .anyRequest().authenticated()  // Require authentication for URLs starting with "/v1/"
//                       .and()
//                   .formLogin(); // Enable form-based authentication
//
//               return http.build();
//           }
//	
//	
//	  @Override
//	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//	        auth.authenticationProvider(authenticatonProvider());
//	    }
//
//	
//	
//	@Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                //.antMatchers("/public").permitAll()
//                .antMatchers("/v1").hasRole("ADMIN")
//                .antMatchers("/v2").hasRole("CUSTOMER")
//                .anyRequest().authenticated()
//                .and()
//            .formLogin()
//                .and()
//            .httpBasic();
//    }

	
//    @Bean
//    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//            .antMatcher("/v1/**")
//            .authorizeRequests()
//                .antMatchers("/v1/test").hasRole("ADMIN")
//                .antMatchers("/v1/flight").hasRole("ADMIN")
//                .and()
//            .formLogin()
//                .loginPage("/v1/login")
//                .and()
//            .logout()
//                .logoutUrl("/v1/logout");
//
//        return http.build();
//    }
//
//    @Bean
//    public SecurityFilterChain customerSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//            .antMatcher("/v2/**")
//            .authorizeRequests()
//                .antMatchers("/v2/register").hasRole("CUSTOMER")
//                .antMatchers("/v2/delete").hasRole("CUSTOMER")
//                .and()
//            .formLogin()
//                .loginPage("/v2/login")
//                .and()
//            .logout()
//                .logoutUrl("/v2/logout");
//
//        return http.build();
//    }
    
    
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//            .authorizeRequests()
//               // .antMatchers("/v1/test").permitAll()
//                .antMatchers("/v1").hasRole("ADMIN")
//                .antMatchers("/v2").hasRole("CUSTOMER")
//                .anyRequest().authenticated()
//                .and()
//            .formLogin()
//                .and()
//            .logout()
//                .logoutSuccessUrl("/login")
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID")
//                .and()
//            .csrf().disable();
//
//        return http.build();
//    }
	

	
	


	 
	  
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

	
//	protected void configure(HttpSecurity http) throws Exception {
//	    http.authorizeRequests()
//	    .antMatchers("/v2/register").permitAll()
//	    .antMatchers("/v2/registration-success").permitAll()
//	    .antMatchers("/login", "/css/**", "/js/**").permitAll()
//	        .antMatchers("/v1/**").hasAuthority("ADMIN")
//	        .antMatchers("/v2/**").hasAuthority("CUSTOMER")
//	        .anyRequest().authenticated()
//	        .and()
//	        .formLogin()
//            .loginPage("/login") // Specify the login page
//            .defaultSuccessUrl("/dashboard", true) // Redirect to the dashboard on successful login
//            .permitAll()
//        .and()
//        .logout()
//            .logoutSuccessUrl("/login")
//            .invalidateHttpSession(true)
//            .deleteCookies("JSESSIONID");
////	        .formLogin().permitAll()
////	        .and()
////	        .logout().permitAll()
////	        .and()
////	        .exceptionHandling().accessDeniedHandler(new CustomAccessDeniedHandler()) // Provide your custom access denied handler
////	        .and()
////	        .csrf().disable()
////	        .headers().frameOptions().disable();
//	}


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
