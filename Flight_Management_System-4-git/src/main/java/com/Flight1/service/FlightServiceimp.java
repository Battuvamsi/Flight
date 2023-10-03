package com.Flight1.service;


import java.time.LocalDate;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import com.Flight1.model.Flights;
import com.Flight1.repository.FlightsRepository;


@Service
public class FlightServiceimp implements FlightService {
	
	@Autowired
	FlightsRepository flightrep;

	@Override
	public void addflight(Flights flight) {
		// TODO Auto-generated method stub
		flightrep.save(flight);
		
	}

	@Override
	public Flights updatebyid( Flights flight) {
		// TODO Auto-generated method stub
		System.out.println("Saving flight: " + flight);

		return flightrep.save(flight);
		
		
	}
	  @Override
	    public boolean deletebyid(int flight_id) {
	        try {
	            flightrep.deleteById(flight_id);
	            return true; // Deletion successful
	        } catch (EmptyResultDataAccessException ex) {
	            // The flight with the given flight_id does not exist
	            return false;
	        } catch (Exception ex) {
	            // Other exceptions, e.g., database connection issues, etc.
	            return false;
	        }
	    }
	@Override
	public Flights getbyId(int id) {
		// TODO Auto-generated method stub
		 Flights flight=flightrep.findById(id).get();
			return flight;
		
	}

	@Override
	public Flights findByproductname(String flight_name) {
		// TODO Auto-generated method stub
		//Flights flight=flightrep.findByflight_name(flight_name);
		return null;
	}

	@Override
	public List<Flights> fetchAllUsers() {
		// TODO Auto-generated method stub
		 List<Flights> flights = flightrep.findAll();
		 return flights;
		
	}

	 public Flights updateFlightById(int flight_id, Flights newFlight) {
	        Flights existingFlight = getbyId(flight_id);
	        if (existingFlight != null) {
	            // Update the existing flight object with newFlight properties
	            existingFlight.setFlight_name(newFlight.getFlight_name());
	            existingFlight.setDate(newFlight.getDate());
	            existingFlight.setFlight_source(newFlight.getFlight_source());
	            existingFlight.setFlight_destination(newFlight.getFlight_destination());
	            existingFlight.setFlight_price(newFlight.getFlight_price());
	            existingFlight.setFlight_duration(newFlight.getFlight_duration());
	            existingFlight.setFlight_capacity(newFlight.getFlight_capacity());

	            // Save the updated flight object
	            return flightrep.save(existingFlight);
	        }
	        return null;
	    }
	 
	 
	 public List<Flights> searchFlights(String flightSource, String flightDestination, LocalDate date) {
	        return flightrep.findFlightsBySourceDestinationAndDate(flightSource, flightDestination, date);
	    }

}
