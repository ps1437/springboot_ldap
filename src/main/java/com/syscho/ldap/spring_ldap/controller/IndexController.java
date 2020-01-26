package com.syscho.ldap.spring_ldap.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.syscho.ldap.spring_ldap.vo.LoginReqVo;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@RestController
@RequestMapping("/auth")
public class IndexController {

	@Autowired
	AuthenticationManager mgr;

	@ApiOperation(value = "Login Request")
	@ApiResponses(value = { @ApiResponse(code = 200, message = "Login Success"),
			@ApiResponse(code = 401, message = "Invalid credentials"),
			@ApiResponse(code = 500, message = "Server Error"), })
	@PostMapping("/login")
	public ResponseEntity<?> data(@RequestBody LoginReqVo loginReqVo) {
		String username = StringUtils.trimAllWhitespace(loginReqVo.getUsername());
		String password = StringUtils.trimAllWhitespace(loginReqVo.getPassword());
		Authentication authenticate = mgr.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		Object principal = authenticate.getPrincipal();

		return ResponseEntity.status(HttpStatus.OK).body(principal);

	}

	@GetMapping("/logout")
	public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication != null) {
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}

		return ResponseEntity.ok("Logout SuccessFull");
	}

	@ExceptionHandler
	public ResponseEntity<?> unauth(BadCredentialsException exp) {
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid  Credentials");
	}
}
