package com._Backend_auth.PkgAuth.controller;

import com._Backend_auth.PkgAuth.dto.HelloResponse;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin("*")
@RestController
@RequestMapping("/api")
public class HelloController {

    @GetMapping("/hello")
    public HelloResponse hello(){
        return new HelloResponse("Hello from Authorized API request.");
    }

}
