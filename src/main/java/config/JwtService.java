package config;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
    // Secret Key utilizada para firmar y verificar los tokens JWT.
    // En un entorno productivo, la clave no debería estar hardcodeada aquí.
    // En su lugar, se recomienda almacenarla en un gestor de secretos (por ejemplo, AWS Secrets Manager, HashiCorp Vault, etc.).
	private static final String SECRET_KEY = "01234527aa08e384029f7dcd740e80cc7555f904e322b9edbd3c9d3ca78f97c5";

    /**
     * Método para obtener el nombre de usuario (subject) del token JWT.
     * 
     * @param token El token JWT del cual extraer el nombre de usuario.
     * @return El nombre de usuario presente en el token.
     */
	public String getUserName(String token) {
		
		return getClaim(token, Claims::getSubject);
	}

	
    /**
     * Método genérico para extraer un "claim" específico del token JWT.
     * Los "claims" son los datos almacenados en el payload del token.
     * 
     * @param <T> El tipo de dato del "claim".
     * @param token El token JWT del cual extraer el claim.
     * @param claimsResolver Una función que especifica qué claim extraer.
     * @return El valor del claim extraído.
     */
	public <T> T getClaim(String token, Function <Claims, T> claimsResolver) {

		final Claims claims = getAllClaims(token);// Extrae todos los claims del token.
		return claimsResolver.apply(claims); // Aplica la función especificada para obtener el claim deseado.
	}

	
	
    /**
     * Obtiene todos los claims presentes en el token JWT.
     * Este método decodifica el token utilizando la clave secreta configurada.
     * 
     * @param token El token JWT del cual extraer los claims.
     * @return Los claims presentes en el token.
     */
	private Claims getAllClaims(String token) {

		return Jwts
				.parserBuilder()
				.setSigningKey(getSingInKey())// Configura la clave para verificar la firma del token.
				.build()
				.parseClaimsJws(token)// Decodifica y verifica el token.
				.getBody();// Obtiene el payload del token.
	}

	
    /**
     * Convierte la clave secreta en un objeto `Key` adecuado para firmar y verificar JWTs.
     * La clave se decodifica desde Base64 y se utiliza para generar una clave HMAC-SHA.
     * 
     * @return La clave utilizada para firmar/verificar tokens.
     */
	private Key getSingInKey() {
		
		// Decodifica la clave secreta desde Base64.
		byte[] keyBites = Decoders.BASE64.decode(SECRET_KEY);
		
        // Genera la clave HMAC-SHA utilizando la clave decodificada.
		return Keys.hmacShaKeyFor(keyBites);
	}


	public boolean validateToken(String token, UserDetails userDetails) {
		
		final String username = getUserName(token);
		
		return (username.equals(userDetails.getUsername()) && !isTkenExpired(token));
	}


	private boolean isTkenExpired(String token) {
		
		return getExpiration(token).before(new Date());
	}


	private Date getExpiration(String token) {
		
		return getClaim(token, Claims::getExpiration);
	}
}
