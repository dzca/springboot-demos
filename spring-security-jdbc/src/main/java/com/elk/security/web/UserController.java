package com.elk.security.web;

import com.elk.security.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequestMapping("/api")
@RestController
public class UserController {
	@GetMapping("/user/{id}")
	@ResponseStatus(HttpStatus.OK)
	User getUser(@PathVariable("id") String id) {
		log.info("calling user service....");
		return new User("Annie", 33);
	}
}
