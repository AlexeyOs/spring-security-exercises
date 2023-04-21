package com.luxoft.spingsecurity.basicauth.rest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginPageController {
    @GetMapping("/login")
    public String loginPage() {
        return "login"; // templates/login.html
    }
}