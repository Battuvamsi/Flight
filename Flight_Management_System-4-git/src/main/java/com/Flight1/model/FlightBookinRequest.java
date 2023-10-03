package com.Flight1.model;

import java.time.LocalDate;

public class FlightBookinRequest {
	
	    private int customerId;
	    private int flightId;
	    private int seatNumber;
	    private LocalDate newDate;
	    private String newName;
	    
	    public FlightBookinRequest() {
			super();
		}
	    
		public FlightBookinRequest(int customerId, int flightId, int seatNumber, LocalDate newDate, String newName) {
			super();
			this.customerId = customerId;
			this.flightId = flightId;
			this.seatNumber = seatNumber;
			this.newDate = newDate;
			this.newName = newName;
		}


	    
	    
		public int getCustomerId() {
			return customerId;
		}


		public void setCustomerId(int customerId) {
			this.customerId = customerId;
		}


		public int getFlightId() {
			return flightId;
		}


		public void setFlightId(int flightId) {
			this.flightId = flightId;
		}


		public int getSeatNumber() {
			return seatNumber;
		}


		public void setSeatNumber(int seatNumber) {
			this.seatNumber = seatNumber;
		}


		public LocalDate getNewDate() {
			return newDate;
		}


		public void setNewDate(LocalDate newDate) {
			this.newDate = newDate;
		}


		public String getNewName() {
			return newName;
		}


		public void setNewName(String newName) {
			this.newName = newName;
		}


	

		
	    
	    
	}



