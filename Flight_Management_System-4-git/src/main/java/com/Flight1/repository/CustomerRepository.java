package com.Flight1.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Flight1.model.Customer;

@Repository
public interface CustomerRepository extends JpaRepository<Customer,Integer> {

	//Customer findBycustomer_id(int customer_id);

	//Customer findBycustomer_name(String customer_name);

	//Customer findByUsername(String username);

	//Customer findBycustomer_username(String customer_username);
	
	public Optional<Customer> findByUsername(String username);
	
	
    Customer findByResetToken(String resetToken);
	
	

}
