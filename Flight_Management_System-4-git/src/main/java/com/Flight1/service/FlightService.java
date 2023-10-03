package com.Flight1.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.Flight1.model.Flights;


public interface FlightService {

	void addflight(Flights flight);

	//void updatebyid(int id, Flights flight);

	Flights updatebyid(Flights flight);

	boolean deletebyid(int flight_id);

	Flights getbyId(int id);

	Flights findByproductname(String flight_name);

	List<Flights> fetchAllUsers();

	Flights updateFlightById(int flight_id, Flights flight);
	

}
