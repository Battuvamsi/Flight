package com.Flight1.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.Flight1.model.Flights;

import java.time.LocalDate;
import java.util.List;

public interface FlightsRepository extends JpaRepository<Flights, Integer> {
	// List<Flights> findByFlight_sourceAndFlight_destinationAndDate(String flight_source, String flight_destination, LocalDate date);
	 
	 
	 @Query("SELECT f FROM Flights f WHERE f.flight_source = ?1 AND f.flight_destination = ?2 AND f.date = ?3")
	    List<Flights> findFlightsBySourceDestinationAndDate(String source, String destination, LocalDate date);
}

