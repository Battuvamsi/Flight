package com.Flight1.model;

import java.time.LocalDate;
import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Flights {
	

	@Id
	int flight_id;
	String flight_name;
	LocalDate date;
	String flight_source;
	String flight_destination;
	Double flight_price;
	Double flight_duration;
	int flight_capacity;
	
	
	
	public Flights() {
		super();
	}



	public Flights(int flight_id, String flight_name, LocalDate date, String flight_source, String flight_destination,
			Double flight_price, Double flight_duration, int flight_capacity) {
		super();
		this.flight_id = flight_id;
		this.flight_name = flight_name;
		this.date = date;
		this.flight_source = flight_source;
		this.flight_destination = flight_destination;
		this.flight_price = flight_price;
		this.flight_duration = flight_duration;
		this.flight_capacity = flight_capacity;
	}



	public int getFlight_id() {
		return flight_id;
	}



	public void setFlight_id(int flight_id) {
		this.flight_id = flight_id;
	}



	public String getFlight_name() {
		return flight_name;
	}



	public void setFlight_name(String flight_name) {
		this.flight_name = flight_name;
	}



	public LocalDate getDate() {
		return date;
	}



	public void setDate(LocalDate newDate) {
		this.date = newDate;
	}



	public String getFlight_source() {
		return flight_source;
	}



	public void setFlight_source(String flight_source) {
		this.flight_source = flight_source;
	}



	public String getFlight_destination() {
		return flight_destination;
	}



	public void setFlight_destination(String flight_destination) {
		this.flight_destination = flight_destination;
	}



	public Double getFlight_price() {
		return flight_price;
	}



	public void setFlight_price(Double flight_price) {
		this.flight_price = flight_price;
	}



	public Double getFlight_duration() {
		return flight_duration;
	}



	public void setFlight_duration(Double flight_duration) {
		this.flight_duration = flight_duration;
	}



	public int getFlight_capacity() {
		return flight_capacity;
	}



	public void setFlight_capacity(int flight_capacity) {
		this.flight_capacity = flight_capacity;
	}



	@Override
	public String toString() {
		return "Flights [flight_id=" + flight_id + ", flight_name=" + flight_name + ", date=" + date
				+ ", flight_source=" + flight_source + ", flight_destination=" + flight_destination + ", flight_price="
				+ flight_price + ", flight_duration=" + flight_duration + ", flight_capacity=" + flight_capacity + "]";
	}



	
	
	
	
	
	
	
	
	


}
