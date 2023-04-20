package com.luxoft.spingsecurity.loginform.rest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginPageController {

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // templates/login.html
    }
}
