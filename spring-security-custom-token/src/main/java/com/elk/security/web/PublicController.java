package com.elk.security.web;

import com.elk.security.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequestMapping("/public")
@RestController
public class PublicController {
	@GetMapping("/home")
	@ResponseStatus(HttpStatus.OK)
	String home() {
		return "Home Page";
	}
}
