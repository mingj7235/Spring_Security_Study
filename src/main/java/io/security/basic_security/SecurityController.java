package io.security.basic_security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping ("/")
    public String index() {
        return "home";
    }


}
