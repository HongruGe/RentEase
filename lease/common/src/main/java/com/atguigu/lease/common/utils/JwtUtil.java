package com.atguigu.lease.common.utils;

import com.atguigu.lease.common.exception.LeaseException;
import com.atguigu.lease.common.result.ResultCodeEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.rmi.dgc.Lease;
import java.util.Date;

public class JwtUtil {
    private static SecretKey tokenSignKey = Keys.hmacShaKeyFor("M0PKKI6pYGVWWfDZw90a0lTpGYX1d4AQ".getBytes());
    public static String createToken(Long userId, String userName) {
        String jwt = Jwts.builder().setSubject("LOGIN_USER").claim("userId", userId).claim("userName", userName).setExpiration(new Date(System.currentTimeMillis() + 3600000)).signWith(tokenSignKey, SignatureAlgorithm.HS256).compact();
        return jwt;
    }
    public static Claims parseToken(String token) {
        if(token==null){
            throw new LeaseException(ResultCodeEnum.ADMIN_LOGIN_AUTH);
        }
        try{
            JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(tokenSignKey).build();
            Jws<Claims> claims = jwtParser.parseClaimsJws(token);
            return claims.getBody();
        } catch (ExpiredJwtException e){
            throw new LeaseException(ResultCodeEnum.TOKEN_EXPIRED);
        } catch (JwtException e){
            throw new LeaseException(ResultCodeEnum.TOKEN_INVALID);
        }

    }

    public static void main(String[] args) {
        String token = JwtUtil.createToken(2L, "user");
        System.out.println(token);
    }
}
