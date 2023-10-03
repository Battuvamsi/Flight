package com.Flight1.repository;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Flight1.model.Booking;
import com.Flight1.model.Customer;



@Repository
	public interface BookingRepository extends JpaRepository<Booking, Long> {
	    List<Booking> findByCustomer(Customer customer);

	
	    
	   
	}



