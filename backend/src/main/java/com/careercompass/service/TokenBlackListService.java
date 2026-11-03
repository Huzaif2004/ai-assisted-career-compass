package com.careercompass.service;

import java.util.Date;

public interface TokenBlackListService {
    void blackList(String jti,Date expiration);
    boolean isBlackListed(String jti);
    
}
