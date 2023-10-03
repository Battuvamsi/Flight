package com.Flight1.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.Flight1.dto.UserinfoUserDetails;
import com.Flight1.model.Customer;
import com.Flight1.repository.CustomerRepository;

public class UserinfoUserDeatailsService implements UserDetailsService{
	
	@Autowired
	private CustomerRepository custrepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		Optional<Customer> customer=custrepo.findByUsername(username);
		
		return customer.map(UserinfoUserDetails::new)
				.orElseThrow(()->new UsernameNotFoundException("User not found"));
	}

}
