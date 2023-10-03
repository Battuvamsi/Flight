package com.Flight1.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.Flight1.model.Customer;
import com.Flight1.repository.CustomerRepository;

@Service
public class CustomerServiceimp implements CustomerService{
	
	@Autowired
	CustomerRepository custmerrep;

	@Override
	public Customer registerCustomer(Customer customer) {
		return custmerrep.save(customer);
	}
	
	
	@Override
	public void resetPassword(int customer_id, String newPassword) {
		// TODO Auto-generated method stub
		 Customer customer = custmerrep.findById(customer_id).get();
	        if (customer != null) {
	            customer.setPassword(newPassword);
	            custmerrep.save(customer);
	        }
		
	}
	
	

	@Override
	public Customer updateCustomer(Customer customer) {
		// TODO Auto-generated method stub
		return custmerrep.save(customer);
	}



	@Override
	public void deleteCustomer(int customer_id) {
		// TODO Auto-generated method stub
		custmerrep.deleteById(customer_id);
		
	}


	@Override
	public List<Customer> getAllCustomers() {
        return custmerrep.findAll();
    }


    @Override
    public Customer getCustomerById(int customerId) {
        return custmerrep.findById(customerId).orElse(null);
    }


    public Optional<Customer> getCurrentCustomer(String username) {
        return custmerrep.findByUsername(username);
    }


	@Override
	public Customer getCustomerProfile(int customerId) {
        return custmerrep.findById(customerId).orElse(null);
                
    }

	

}
