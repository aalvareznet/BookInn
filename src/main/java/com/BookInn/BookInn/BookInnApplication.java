package com.BookInn.BookInn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Component;

@SpringBootApplication
@ComponentScan("com.bookinn")
public class BookInnApplication {

	public static void main(String[] args) {
		SpringApplication.run(BookInnApplication.class, args);
	}

}
