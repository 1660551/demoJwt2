package vn.giasutinhoc.demo.jwt.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import vn.giasutinhoc.demo.jwt.common.ERole;
import vn.giasutinhoc.demo.jwt.common.JwtUtils;
import vn.giasutinhoc.demo.jwt.dto.JwtResponse;
import vn.giasutinhoc.demo.jwt.dto.LoginRequest;
import vn.giasutinhoc.demo.jwt.dto.MessageResponse;
import vn.giasutinhoc.demo.jwt.dto.SignupRequest;
import vn.giasutinhoc.demo.jwt.entities.Role;
import vn.giasutinhoc.demo.jwt.entities.User;
import vn.giasutinhoc.demo.jwt.reponsitories.RoleRepository;
import vn.giasutinhoc.demo.jwt.reponsitories.UserRepository;
import vn.giasutinhoc.demo.jwt.service.UserDetailsImpl;

@CrossOrigin
@RestController
@RequestMapping("/api/auth")
public class AuthController {

//	@Autowired
//    private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	RoleRepository roleRepository;
	
	@Autowired
	JwtUtils jwtUtils;
	 
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Validated @RequestBody LoginRequest loginRequest) throws Exception{
		
		String username = loginRequest.getUsername();
		String password = loginRequest.getPassword();
		
//		  String passwd = encoder.encode("123456");
//
//	      // passwd - password from database
//	      System.out.println(passwd); // print hash
//
//	      boolean test = encoder.matches("123456", passwd);
//	      
//	      // true for all 5 iteration
//	      System.out.println(test);
//		
//	      
//	      
//		String passwordtest = "stackjava.com";
//		String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
//		System.out.println("BCrypt hash: " + hash);
//		
//		boolean valuate = BCrypt.checkpw(passwordtest,
//				hash);
//		
//		System.out.println(valuate);
		
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(  username
						,password));
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
		
		return ResponseEntity.ok(new JwtResponse(jwt, 
													userDetails.getId(), 
													userDetails.getUsername()
													, userDetails.getEmail()
													, roles));
	}
	
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Validated @RequestBody SignupRequest signupRequest){
		if(userRepository.existsByUsername(signupRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
				
		}
		if(userRepository.existsByEmail(signupRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already taken!"));
		}
		
		//Create new user
		User user = new User(signupRequest.getUsername(), signupRequest.getEmail()
				,encoder.encode(signupRequest.getPassword()));
		
		Set<String> strRoles = signupRequest.getRole();
		Set<Role> roles = new HashSet<>();
		
		if(strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: role is not found"));
			roles.add(userRole);
		}else 
		{
			strRoles.forEach(role ->{
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
						.orElseThrow(() -> new RuntimeException("Error: role is not found"));
					roles.add(adminRole);
					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
						.orElseThrow(() -> new RuntimeException("Error: role is not found"));
					roles.add(modRole);
					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
						.orElseThrow(() -> new RuntimeException("Error: role is not found"));
					roles.add(userRole);
				}
			});
		}
		
		user.setRoles(roles);
		userRepository.save(user);
		
		return ResponseEntity.ok(new MessageResponse("User registered successfully"));
	}
}
