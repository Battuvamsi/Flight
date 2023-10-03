package com.Flight1.controller;

import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpSession;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.Flight1.model.Booking;
import com.Flight1.model.Customer;
import com.Flight1.model.FlightBookinRequest;
import com.Flight1.model.Flights;
import com.Flight1.repository.BookingRepository;
import com.Flight1.repository.CustomerRepository;
import com.Flight1.repository.FlightsRepository;
import com.Flight1.service.BookingService;
import com.Flight1.service.CustomerServiceimp;
import com.Flight1.service.FlightServiceimp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
public class BookingController {
	
	
	    @Autowired
	    private BookingService bookingService;
	    
	    @Autowired
	    private FlightServiceimp flightService;
	    
	    @Autowired
	    private CustomerServiceimp customerservice;
	    
	    @Autowired
	    private BookingRepository bookingRepository;
	    
	    @Autowired
	    FlightsRepository flightRepository;
	    
	    @Autowired
	    CustomerRepository customerRepository;
	    
	    
	    

	    @GetMapping("/customer-dashboard")
	    public ResponseEntity<Optional<Customer>> getCustomerDashboard(Authentication authentication) {
	        // Get the currently logged-in user's username from the authentication object
	        String username = authentication.getName();

	        // Use the username to fetch the customer information
	        Optional<Customer> customer = customerservice.getCurrentCustomer(username);

	        if (customer != null) {
	            return ResponseEntity.ok(customer);
	        } else {
	            return ResponseEntity.notFound().build();
	        }
	    }
	    
	    
	    
	    
	    @GetMapping("/search")
	    public ResponseEntity<List<Flights>> searchFlights(
	            @RequestParam("source") String source,
	            @RequestParam("destination") String destination,
	            @RequestParam("date") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
	        List<Flights> flights = flightService.searchFlights(source, destination, date);
	        return ResponseEntity.ok(flights);
	    }
	    
//	    @PostMapping("/book-flight")
//	    public ResponseEntity<Booking> bookFlight(@RequestBody FlightBookinRequest bookingRequest) {
//	        Booking booking = bookingService.bookFlight(bookingRequest.getCustomerId(), bookingRequest.getFlightId(), bookingRequest.getSeatNumber());
//	        if (booking != null) {
//	            return ResponseEntity.ok(booking);
//	        } else {
//	            return ResponseEntity.badRequest().build();
//	        }
//	    }
	    
	    
	    @GetMapping("/details-filling")
	    public String showDetailsFillingPage(
	            @RequestParam("flightId") int flightId,
	            @RequestParam("flightName") String flightName
	           
	            
	    ) {
	        // Your code to show the details filling page
	        // You can use the flightId and flightName parameters here
	        return "details_filling"; // Return the name of the HTML page to display
	    }
	    
	    @GetMapping("/booking_success_test")
	    public String showBookingSuccessTestPage() {
	        return "booking_success.html";
	    }

	    @GetMapping("/booking_success")
	    public String showBookingSuccessPage() {
	        return "booking_success"; // This should resolve to "booking_success.html" inside the templates folder
	    }
	    
	    
	    @GetMapping("/payment")
	    public String showpayment() {
			return "payment";
	    	
	    }
	    
	 // Mock payment endpoint to handle payment form submission
	    @PostMapping("/payment")
	    public String processPayment(@RequestParam("cardNumber") String cardNumber, 
	                                 @RequestParam("expiryDate") String expiryDate, 
	                                 @RequestParam("cvv") String cvv,
	                                 @RequestParam ("Name") String Name, Model model) {
	        // Here, you can implement the mock payment processing logic
	        // For simplicity, we will assume payment is successful if all fields are non-empty
	        if (!cardNumber.isEmpty() && !expiryDate.isEmpty() && !cvv.isEmpty() && !Name.isEmpty()) {
	            return "redirect:/payment"; // Redirect to the booking success page
	        } else {
	            model.addAttribute("error", "Payment failed. Please fill out all payment details.");
	            return "payment"; // Return back to the payment page with an error message
	        }
	    }


	    
		 

	    @PostMapping("/book-flight/{flightId}")
	    public String bookFlight(@PathVariable int flightId,@RequestParam int customerId) {
	        // Here, you can implement the logic to book the flight with the given flightId
	        // For simplicity, let's assume the booking is successful
	    	
	    	 System.out.println("Received flightId: " + flightId);
	    	    System.out.println("Received customerId: " + customerId);

	        boolean isBookingSuccessful = bookingService.bookFlight(flightId,customerId);
	        if (isBookingSuccessful) {
	        	
	            return "redirect:/booking_success"; // Redirect to the booking success page
	        } else {
	            return "redirect:/booking_failure"; // Return some error view in case of booking failure
	        }
	    }
	   
//
//	    @PostMapping("/book-flight/{flightId}")
//	    public String bookFlight(@PathVariable int flightId, @RequestParam int customerId, @RequestParam int seatNumber) {
//	        boolean isBookingSuccessful = bookingService.bookFlight(flightId, customerId, seatNumber);
//	        if (isBookingSuccessful) {
//	            return "redirect:/booking_success"; // Redirect to the booking success page
//	        } else {
//	            return "redirect:/booking_failure"; // Return some error view in case of booking failure
//	        }
//	    }
	    
//	    private static final Logger LOGGER = LoggerFactory.getLogger(BookingController.class);
//	    @PostMapping("/book-flight/{flightId}")
//	    public String bookFlight(@PathVariable int flightId, HttpSession session) {
//	    	System.out.println("hello rangayya");
//	    	LOGGER.info("Booking flight with ID: {}", flightId);
//	        // Retrieve the flight from the database using the flightId
//	        Optional<Flights> optionalFlight = flightRepository.findById(flightId);
//	        LOGGER.info("Booking flight with1 ID: {}", flightId);
//	        if (optionalFlight.isPresent()) {
//	            Flights flight = optionalFlight.get();
//	            LOGGER.info("Flight details before capacity decrement: {}", flight);
//
//	            // Retrieve the customer ID from the authenticated session
//	            Integer customerId = (Integer) session.getAttribute("customerId");
//	            if (customerId == null) {
//	            	System.out.println("hello ramarao");
//	            	System.out.println(customerId);
//	                // Customer is not authenticated or session expired, so booking cannot be made
//	                return "redirect:/login"; // Redirect to the login page or show an error message
//	            }
//         
//	            // Retrieve the customer from the database using the customer ID
//	            Optional<Customer> optionalCustomer = customerRepository.findById(customerId);
//	            if (!optionalCustomer.isPresent()) {
//	            	System.out.println("hello ram");
//	            	System.out.println(customerId);
//	                // Customer with the provided ID does not exist, so booking cannot be made
//	                return "redirect:/login"; // Redirect to the login page or show an error message
//	            }
//	            System.out.println("hello BEFORE THAT NOT WORKING METHOD");
//            	System.out.println(customerId);
//	            Customer customer = optionalCustomer.get();
//	            System.out.println("hello rangayya");
//	            System.out.println(flight.getFlight_capacity());
//	            // For simplicity, we'll just assume the booking is successful if the flight has available capacity.
//	            if (flight.getFlight_capacity() > 0) {
//	            	System.out.println("hello subbarao");
//	                // Decrement the flight's capacity by one
//	                flight.setFlight_capacity(flight.getFlight_capacity() - 1);
//	                flightRepository.save(flight);
//	                LOGGER.info("Flight details after capacity decrement: {}", flight);
//
//	                // Create a new Booking entity
//	                Booking booking = new Booking();
//	                booking.setCustomer(customer);
//	                booking.setFlight(flight);
//	                booking.setBookingAmount(flight.getFlight_price()); // Use the flight price as the booking amount
//	                booking.setSeatNumber(34); // You need to set the seat number here
//
//	                // Save the new Booking entity to the database
//	                bookingRepository.save(booking);
//
//	                return "redirect:/booking_success"; // Redirect to the booking success page
//	            }
//	        }
//	        return "redirect:/booking_failure"; // Return some error view in case of booking failure
//	    }
//
//	      
	    
	    @PostMapping("/cancel-booking/{bookingId}")
	    public ResponseEntity<String> cancelBooking(@PathVariable Long bookingId) {
	        boolean canceled = bookingService.cancelBooking(bookingId);
	        if (canceled) {
	            return ResponseEntity.ok("Booking canceled successfully");
	        } else {
	            return ResponseEntity.notFound().build();
	        }
	    }
	    
	    @PutMapping("/modify-booking/{bookingId}")
	    public ResponseEntity<Booking> modifyBooking(@PathVariable Long bookingId, @RequestBody FlightBookinRequest bookingRequest) {
	        Booking modifiedBooking = bookingService.modifyBooking(bookingId, bookingRequest.getNewDate(), bookingRequest.getNewName());
	        if (modifiedBooking != null) {
	            return ResponseEntity.ok(modifiedBooking);
	        } else {
	            return ResponseEntity.notFound().build();
	        }
	    }
//	    @GetMapping("/booking-history")
//	    public ResponseEntity<List<Booking>> getBookingHistory(@RequestParam("customerId") int customerId) {
//	        List<Booking> bookingHistory = bookingService.getBookingHistory(customerId);
//	        if (!bookingHistory.isEmpty()) {
//	            return ResponseEntity.ok(bookingHistory);
//	        } else {
//	            return ResponseEntity.notFound().build();
//	        }
//	    }
	    
	    
	    
	    
	    @GetMapping("/booking-history/{customerId}")
	    public ResponseEntity<List<Booking>> getBookingHistory(@PathVariable int customerId) {
	        List<Booking> bookingHistory = bookingService.getBookingHistory(customerId);
	        if (!bookingHistory.isEmpty()) {
	            return ResponseEntity.ok(bookingHistory);
	        } else {
	            return ResponseEntity.notFound().build();
	        }
	    }

	}



