package entity;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.*;
import lombok.*;


@Entity
@Table(name="tbl_user")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User implements UserDetails{
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(
			strategy= GenerationType.IDENTITY
			)
	private Long id;
	private String firstName;
	private String lastName;
	private String email;
	private String password;
	
	@Enumerated(EnumType.ORDINAL)
	private Role role;
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		return List.of(new SimpleGrantedAuthority(role.name()));
	}
	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return password;
	}
	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return email;
	}

}
