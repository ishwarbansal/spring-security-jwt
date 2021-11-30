package com.bansal.springsecurityjwt.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.bansal.springsecurityjwt.model.AuthenticationRequest;
import com.bansal.springsecurityjwt.model.AuthenticationResponse;
import com.bansal.springsecurityjwt.util.JWTUtil;

@RestController
public class RestSecurityController {

	@Autowired
	private AuthenticationManager auththenticationManager;

	@Autowired
	MyUserDetailsService myUserDetailsService;
	
	@Autowired
	JWTUtil jwtUtils;

	@GetMapping("/hello")
	public String hello() {
		return "Hello !!";
	}

	@RequestMapping(value="/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
		try {
			auththenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword())
					);
		}catch(BadCredentialsException e) {
			throw new Exception("Incorrect user name or password", e);
		}
		
		final UserDetails userDetails =  myUserDetailsService.loadUserByUsername(authenticationRequest.getUserName());
		
		final String jwt = jwtUtils.generateToken(userDetails);
		
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}


}
