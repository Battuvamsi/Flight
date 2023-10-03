package com.Flight1.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.Flight1.model.Customer;
import com.Flight1.model.Flights;
import com.Flight1.service.CustomerService;
import com.Flight1.service.FlightService;



@RestController
@RequestMapping("/v1")
public class AdminController {
	
	
	@Autowired
	FlightService flightser;
	
	@Autowired
	CustomerService customerService;
	
	//@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping("/test")
	public String test()
	{
		return "working good";
	}
	
	
	
	 @GetMapping("/customers")
	    public List<Customer> getAllCustomers() {
	        return customerService.getAllCustomers();
	    }
	
	
	@PostMapping("/flight")
	 //@PreAuthorize("hasAuthority('ADMIN')") 
	//@PreAuthorize("hasRole('ADMIN')")
	public void addflights(@RequestBody Flights flight) {
		 System.out.println("Flight data received: " + flight);
	  flightser.addflight(flight);
		
	}
	
//	 @PutMapping(value="/update/{id}")
//		public void updatebyid(@PathVariable int id, @RequestBody Product product) {
//			
//			 productservice.updatebyid(id,product);
//			
//			
//		}
	
	 @PutMapping("/update/{flight_id}")
	   // @PreAuthorize("hasRole('ADMIN')")
	    public ResponseEntity<Flights> updateFlightById(@PathVariable("flight_id") int flight_id, @RequestBody Flights flight) {
	        Flights updatedFlight = flightser.updateFlightById(flight_id, flight);
	        if (updatedFlight != null) {
	            return new ResponseEntity<>(updatedFlight, HttpStatus.OK);
	        } else {
	            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
	        }
	    }

	
	@DeleteMapping(value="/delete/{flight_id}")
	public ResponseEntity<String> deletebyid(@PathVariable("flight_id") int flight_id) {
	    boolean deleted = flightser.deletebyid(flight_id);
	    if (deleted) {
	        return ResponseEntity.ok("Flight deleted successfully.");
	    } else {
	        return ResponseEntity.notFound().build(); // Or return a response with a specific error message
	    }
	}

	 
	 @GetMapping(value="/get/{id}")
	// @PreAuthorize("hasRole('ADMIN')")
	public Flights getbyid(@PathVariable("id") int id) {
		
		Flights prod = flightser.getbyId(id);
		
		return prod;
	}
	 
	 @GetMapping(value="/fetch/{flight_name}")
		public Flights getbyname(@PathVariable("flight_name") String flight_name) {
			
			Flights flight = flightser.findByproductname(flight_name);
			
			return flight;
		}
	 
	 @RequestMapping("/user")
	// @PreAuthorize("hasRole('ADMIN')")
		public List<Flights> getAllUsers()
		{
			List<Flights> user=flightser.fetchAllUsers();
			return user;
		}
	 
	 


}
