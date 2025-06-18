package com.example.demo.Controller;

import com.example.demo.Service.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/api")
public class EncryptionController {

    @Autowired
    private EncryptionService encryptionService;

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody String plainText) throws Exception {
        return encryptionService.encrypt(plainText);
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody String encryptedText) throws Exception {
        return encryptionService.decrypt(encryptedText);
    }
}
