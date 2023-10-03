package com.Flight1.model;


import javax.persistence.Transient;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

@Entity
public class Booking {
	    @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    @Column(name = "booking_id")
	    private Long bookingId;
	    
	    @ManyToOne
	    @JoinColumn(name = "customer_id")
	    private Customer customer;
	    
	    @ManyToOne
	    @JoinColumn(name = "flight_id")
	    private Flights flight;
	    
	    @Column(name = "booking_amount")
	    private Double bookingAmount;
	    
	    @Column(name = "seat_number")
	    private int seatNumber;
	    
	    // Additional fields to store Source and Destination from the Flights entity
	    
	    private String source;
	    
	   // @Transient
	    private String destination;


		public Booking() {
			super();
		}


		public Booking(Long bookingId, Customer customer, Flights flight, Double bookingAmount, int seatNumber,
				String flight_source, String flight_destination) {
			super();
			this.bookingId = bookingId;
			this.customer = customer;
			this.flight = flight;
			this.bookingAmount = bookingAmount;
			this.seatNumber = seatNumber;
			this.source = flight_source;
			this.destination = flight_destination;
		}


		public Long getBookingId() {
			return bookingId;
		}


		public void setBookingId(Long bookingId) {
			this.bookingId = bookingId;
		}


		public Customer getCustomer() {
			return customer;
		}


		public void setCustomer(Customer customer) {
			this.customer = customer;
		}


		public Flights getFlight() {
			return flight;
		}


		public void setFlight(Flights flight) {
			this.flight = flight;
		}


		public Double getBookingAmount() {
			return bookingAmount;
		}


		public void setBookingAmount(Double bookingAmount) {
			this.bookingAmount = bookingAmount;
		}


		public int getSeatNumber() {
			return seatNumber;
		}


		public void setSeatNumber(int seatNumber) {
			this.seatNumber = seatNumber;
		}


		public String getSource() {
			return source;
		}


		public void setSource(String source) {
			this.source = source;
		}


		public String getDestination() {
			return destination;
		}


		public void setDestination(String destination) {
			this.destination = destination;
		}



	   
	}
	


