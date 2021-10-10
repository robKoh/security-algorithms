package com.hwr.bcrypt;

import org.junit.jupiter.api.Test;

class TestBcryptHashing {

    @Test
    void compareOriginalPwWithHashPw() {
        String originalPassword = "Password1234";
        String generatedSecuredPasswordHash = BCrypt.hashpw(originalPassword, BCrypt.gensalt(12));
        System.out.println(generatedSecuredPasswordHash);

        boolean matched = BCrypt.checkpw(originalPassword, generatedSecuredPasswordHash);
        System.out.println(matched);
    }
}
