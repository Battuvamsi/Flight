package com.Flight1.service;


import java.time.LocalDate;
import java.util.List;

import com.Flight1.model.Booking;

public interface BookingService {

	boolean cancelBooking(Long bookingId);

	//List<Booking> getBookingHistory(Long customerId);

	Booking modifyBooking(Long bookingId, LocalDate newDate, String newName);

	List<Booking> getBookingHistory(int customerId);

//	Booking bookFlight(int customerId, int flightId, int seatNumber);

	//boolean bookFlight(int flightId);

//	boolean bookFlight(int flightId, int customerId, double bookingAmount, int seatNumber);

//	boolean bookFlight(int flightId, double bookingAmount, int seatNumber);

//	boolean bookFlight(int flightId, int customerId, int seatNumber);

	//boolean bookFlight(int flightId);

	//boolean bookFlight(int flightId, int customerId);

	//boolean bookFlight(int flightId);

	boolean bookFlight(int flightId, int customerId);

	//Booking bookFlight(Long customerId, Long flightId, int seatNumber);

}
