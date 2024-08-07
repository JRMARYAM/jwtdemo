package com.example.springsecurityjwt;

import com.example.springsecurityjwt.entities.Role;
import com.example.springsecurityjwt.entities.User;
import com.example.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class  SpringsecurityjwtApplication implements CommandLineRunner
{

	@Autowired
	private UserRepository userRepository;


	public static void main(String[] args) {
		SpringApplication.run(SpringsecurityjwtApplication.class, args);
	}


	@Override
	public void run(String... args) throws Exception{
		User adminAccount = userRepository.findByRole(Role.ADMIN);
		if(null==adminAccount){
			User user=new User();


			user.setEmail("admin@gmail.com");
			user.setFirstname("admin");
			user.setSecondname("admin");
			user.setRole(Role.ADMIN);
			user.setPassword(new BCryptPasswordEncoder().encode("admin"));
			userRepository.save(user);


		}

	}




}
