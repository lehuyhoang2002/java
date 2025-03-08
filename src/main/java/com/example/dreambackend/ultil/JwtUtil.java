package com.example.dreambackend.ultil;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {
    private String secretKey = "0501a20aaed0b5827f4f9517f98e203138494e7bcfe3ca6b1c78666c7d84434473d0be2f8b6927bf616e66614c14a9e3b86339589b98d0b1aba18ecae50ebe5c"; // Thay bằng key bảo mật của bạn

    // Phương thức tạo token
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role) // Thêm quyền vào trong claim
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // Token hết hạn sau 10 giờ
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    // Lấy thông tin từ JWT
    public Claims extractClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }

    // Lấy username từ JWT
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    // Kiểm tra xem token có hợp lệ không
    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    // Kiểm tra tính hợp lệ của JWT
    public boolean validateToken(String token, String username) {
        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
    }
}
