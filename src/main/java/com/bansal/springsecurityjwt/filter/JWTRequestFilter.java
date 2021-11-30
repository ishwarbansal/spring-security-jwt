package com.bansal.springsecurityjwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bansal.springsecurityjwt.service.MyUserDetailsService;
import com.bansal.springsecurityjwt.util.JWTUtil;

@Component
public class JWTRequestFilter extends OncePerRequestFilter{
	
	@Autowired
	MyUserDetailsService myUserDetailsService;
	
	@Autowired
	JWTUtil jwtUtils;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		final String authorizationHeader= request.getHeader("Authorization");
		String userName = null;
		String jwt = null;
		
		if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer ")) {
			jwt = authorizationHeader.substring(7);
			userName = jwtUtils.extractUsername(jwt);
		}
		
		if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails = myUserDetailsService.loadUserByUsername(userName);
			if(jwtUtils.validateToken(jwt, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				
			}
		}
		
		filterChain.doFilter(request, response);
	}

}
