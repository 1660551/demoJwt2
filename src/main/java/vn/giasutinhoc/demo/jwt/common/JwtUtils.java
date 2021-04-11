package vn.giasutinhoc.demo.jwt.common;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import vn.giasutinhoc.demo.jwt.service.UserDetailsImpl;

@Component
public class JwtUtils {
	private static final Logger Logger = LoggerFactory.getLogger(JwtUtils.class);
	
	@Value("${bezkoder.app.jwtSecret}")
	private String jwtSecret ;
	
	@Value("${bezkoder.app.jwtExpirationMs}")
	private int jwtExpirationMs;
	
	public String generateJwtToken(Authentication authentication) {
		UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
		
		return Jwts.builder()
				.setSubject((userPrincipal.getUsername()))
				.setIssuedAt(new Date())
				.setExpiration(new Date((new Date().getTime() + jwtExpirationMs)))
				.signWith(SignatureAlgorithm.HS512, jwtSecret)
				.compact();
	}
	
	public String getUserNameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}
	
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
			return true;
		}catch (SignatureException e) {
			Logger.error("invalid JWT signature: {}", e.getMessage());
			// TODO: handle exception
		}catch (MalformedJwtException e) {
			Logger.error("invalid JWT token: {}", e.getMessage());
			// TODO: handle exception
		}catch (ExpiredJwtException e) {
			Logger.error("invalid JWT expired: {}", e.getMessage());
			// TODO: handle exception
		}catch (UnsupportedJwtException e) {
			Logger.error("invalid JWT Unsupported: {}", e.getMessage());
			// TODO: handle exception
		}catch (IllegalArgumentException e) {
			Logger.error("invalid JWT string empty: {}", e.getMessage());
			// TODO: handle exception
		} 
		return false;
	}
}
