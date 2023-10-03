package com.Flight1.service;

import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.Flight1.model.Booking;
import com.Flight1.model.Customer;
import com.Flight1.model.Flights;
import com.Flight1.repository.BookingRepository;
import com.Flight1.repository.CustomerRepository;
import com.Flight1.repository.FlightsRepository;

@Service
public class BookingServiceimp implements BookingService {
	
	
	    @Autowired
	    private BookingRepository bookingRepository;
	    
	    @Autowired
	    private FlightsRepository flightRepository;
	    
	    @Autowired
	    CustomerRepository customerRepository;
	    
//	    @Override
//	    public boolean bookFlight(int flightId, int customerId) {
//	        // Retrieve the flight from the database using the flightId
//	        Optional<Flights> optionalFlight = flightRepository.findById(flightId);
//	        if (optionalFlight.isPresent()) {
//	            Flights flight = optionalFlight.get();
//
//	            // Here, you can implement the actual booking logic, such as checking seat availability,
//	            // updating the flight's capacity, and saving booking details in a database.
//	            // For simplicity, we'll just assume the booking is successful and update the flight capacity.
//	            if (flight.getFlight_capacity() > 0) {
//	                flight.setFlight_capacity(flight.getFlight_capacity() - 1);
//	                Booking booking = new Booking();
//
//	                // Retrieve the customer from the database using the customerId
//	                Optional<Customer> optionalCustomer = customerRepository.findById(customerId);
//	                if (optionalCustomer.isPresent()) {
//	                    Customer customer = optionalCustomer.get();
//	                    booking.setCustomer(customer); // Set the customer for the booking
//	                } else {
//	                    // Handle the case when the customer is not found
//	                    return false;
//	                }
//
//	                booking.setFlight(flight);
//	                booking.setBookingAmount(flight.getFlight_price()); // Use the flight price as the booking amount
//	                booking.setSeatNumber(34); // You need to set the seat number here
//	                booking.setSource(flight.getFlight_source()); // Set the source from the flight
//	                booking.setDestination(flight.getFlight_destination()); // Set the destination from the flight
//
//	                // Save the new Booking entity to the database
//	                bookingRepository.save(booking);
//	                flightRepository.save(flight); // Update the flight capacity
//	                return true;
//	            }
//	        }
//	        return false;
//	    }
	    
	    @Override
	    public boolean bookFlight(int flightId, int customerId) {
	    	System.out.println("Inside bookFlight method"); 
	        // Retrieve the flight from the database using the flightId
	        Optional<Flights> optionalFlight = flightRepository.findById(flightId);
	        if (optionalFlight.isPresent()) {
	            Flights flight = optionalFlight.get();

	            // Here, you can implement the actual booking logic, such as checking seat availability,
	            // updating the flight's capacity, and saving booking details in a database.
	            // For simplicity, we'll just assume the booking is successful and update the flight capacity.
	            if (flight.getFlight_capacity() > 0) {
	                System.out.println("Flight capacity before booking: " + flight.getFlight_capacity());
	                flight.setFlight_capacity(flight.getFlight_capacity() - 1);
	                System.out.println("Flight capacity after booking: " + flight.getFlight_capacity());

	                Booking booking = new Booking();

	                // Retrieve the customer from the database using the customerId
	                Optional<Customer> optionalCustomer = customerRepository.findById(customerId);
	                if (optionalCustomer.isPresent()) {
	                    Customer customer = optionalCustomer.get();
	                    booking.setCustomer(customer); // Set the customer for the booking
	                } else {
	                    // Handle the case when the customer is not found
	                    return false;
	                }

	                booking.setFlight(flight);
	                booking.setBookingAmount(flight.getFlight_price()); // Use the flight price as the booking amount
	                booking.setSeatNumber(34); // You need to set the seat number here
	                booking.setSource(flight.getFlight_source()); // Set the source from the flight
	                booking.setDestination(flight.getFlight_destination()); // Set the destination from the flight

	                // Save the new Booking entity to the database
	                bookingRepository.save(booking);
	                flightRepository.save(flight); // Update the flight capacity

	                return true;
	            }
	        }
	        return false;
	    }


//	    
	    
//	    @Override
//	    public boolean bookFlight(int flightId, int customerId, int seatNumber) {
//	        // Retrieve the flight from the database using the flightId
//	        Optional<Flights> optionalFlight = flightRepository.findById(flightId);
//	        Optional<Customer> optionalCustomer = customerRepository.findById(customerId);
//
//	        if (optionalFlight.isPresent() && optionalCustomer.isPresent()) {
//	            Flights flight = optionalFlight.get();
//	            Customer customer = optionalCustomer.get();
//
//	            // For simplicity, we'll just assume the booking is successful if the flight has available capacity.
//	            if (flight.getFlight_capacity() > 0) {
//	                // Decrement the flight's capacity by one
//	                flight.setFlight_capacity(flight.getFlight_capacity() - 1);
//	                flightRepository.save(flight);
//
//	                // Create a new Booking entity
//	                Booking booking = new Booking();
//	                booking.setCustomer(customer);
//	                booking.setFlight(flight);
//	                booking.setBookingAmount(flight.getFlight_price()); // Set the booking amount from the Flights entity
//	                booking.setSeatNumber(seatNumber);
//
//	                // Save the new Booking entity to the database
//	                bookingRepository.save(booking);
//
//	                return true;
//	            }
//	        }
//	        return false;
//	    }


//	    public Booking bookFlight(int customerId, int flightId, int seatNumber) {
//	        Optional<Customer> optionalCustomer = customerRepository.findById(customerId);
//	        Optional<Flights> optionalFlight = flightRepository.findById(flightId);
//	        
//	        if (optionalCustomer.isPresent() && optionalFlight.isPresent()) {
//	            Customer customer = optionalCustomer.get();
//	            Flights flight = optionalFlight.get();
//	            
//	            if (flight.getFlight_capacity() > 0) {
//	                Booking booking = new Booking();
//	                booking.setCustomer(customer);
//	                booking.setFlight(flight);
//	                booking.setBookingAmount(flight.getFlight_price());
//	                booking.setSeatNumber(seatNumber);
//	                
//	                flight.setFlight_capacity(flight.getFlight_capacity() - 1);
//	                
//	                bookingRepository.save(booking);
//	                flightRepository.save(flight);
//	                
//	                return booking;
//	            }
//	        }
//	        return null;
//	    }
	    
	    public boolean cancelBooking(Long bookingId) {
	        Optional<Booking> optionalBooking = bookingRepository.findById(bookingId);
	        if (optionalBooking.isPresent()) {
	            Booking booking = optionalBooking.get();
	            
	            Flights flight = booking.getFlight();
	            flight.setFlight_capacity(flight.getFlight_capacity() + 1);
	            
	            bookingRepository.delete(booking);
	            flightRepository.save(flight);
	            
	            return true;
	        }
	        return false;
	    }
	    
	    public Booking modifyBooking(Long bookingId, LocalDate newDate, String newName) {
	        Optional<Booking> optionalBooking = bookingRepository.findById(bookingId);
	        if (optionalBooking.isPresent()) {
	            Booking booking = optionalBooking.get();
	            
	            Flights flight = booking.getFlight();
	            flight.setDate(newDate);
	            flight.setFlight_name(newName);
	            
	            flightRepository.save(flight);
	            
	            return booking;
	        }
	        return null;
	    }
	    
	    public List<Booking> getBookingHistory(int customerId) {
	        Optional<Customer> optionalCustomer = customerRepository.findById(customerId);
	        if (optionalCustomer.isPresent()) {
	            Customer customer = optionalCustomer.get();
	            return bookingRepository.findByCustomer(customer);
	        }
	        return Collections.emptyList();
	    }
	    
//	    public List<Booking> getBookingHistory(int customerId) {
//	        // Use the bookingRepository to fetch the booking history for the given customerId
//	        // Assuming that the bookingRepository has a method to fetch bookings by customerId
//	        return bookingRepository.findById(customerId);
//	    }

//		@Override
//		public Booking bookFlight(int customerId, int flightId, int seatNumber) {
//			// TODO Auto-generated method stub
//			return null;
//		}

//		@Override
//		public List<Booking> getBookingHistory(Long customerId) {
//			// TODO Auto-generated method stub
//			return null;
//		}

//		@Override
//		public Booking bookFlight(Long customerId, Long flightId, int seatNumber) {
//			// TODO Auto-generated method stub
//			return null;
//		}

	


}
