package config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter{
	
	private final UserDetailsService userDetailService;
	
	private final JwtService jwtService;

	
	public JwtFilter(UserDetailsService userDetailService) {
		super();
		this.userDetailService = userDetailService;
		this.jwtService = new JwtService();
	}


	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, 
									@NonNull HttpServletResponse response, 
									@NonNull FilterChain filterChain) throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");// Recupera el encabezado de autorización de la solicitud HTTP.
		final String jwt;
		final String userEmail;
		
		// Verifica si el encabezado de autorización existe y si empieza con "Bearer" (tipo de autenticación utilizado para los tokens JWT).
        // Si no es así, pasa la solicitud al siguiente filtro sin realizar ninguna validación adicional.
		if(authHeader == null || !authHeader.startsWith("Bearer")) {
			filterChain.doFilter(request, response);// Continua con el siguiente filtro.
			return;// Termina la ejecución de este filtro.
		}
		
		//se le sacan al token los 7 caracteres de "bearer" mas un espacio, luego viene e token
		jwt = authHeader.substring(7);
		
		
        // Extrae el token JWT del encabezado de autorización (eliminando "Bearer ").
		userEmail = jwtService.getUserName(jwt);
		
        // Verifica si el email del usuario es válido y si el usuario no ha sido autenticado previamente.
		if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Carga los detalles del usuario a partir del email utilizando el UserDetailsService. 
			UserDetails userDetails = this.userDetailService.loadUserByUsername(userEmail);
			
			
            // Valida el token JWT utilizando el jwtService. Si es válido, crea un objeto de autenticación.
			if(jwtService.validateToken(jwt, userDetails)) {
				
                // Crea un token de autenticación utilizando el email y las autoridades del usuario.
				UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, 
						null, // No se necesita la contraseña para la autenticación basada en JWT.
						userDetails.getAuthorities());// Se asignan las autoridades del usuario.
				
				
                // Asocia detalles adicionales con la autenticación (como la IP de la solicitud, entre otros).
				authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
                // Establece el token de autenticación en el contexto de seguridad de Spring.
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			}
		}
		
		
		// Pasa la solicitud al siguiente filtro en la cadena.
		filterChain.doFilter(request, response);
	}
	
	

}
