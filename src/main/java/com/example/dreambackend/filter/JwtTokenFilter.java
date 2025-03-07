package com.example.dreambackend.filter;

import com.example.dreambackend.ultil.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
@Component
public class JwtTokenFilter extends OncePerRequestFilter {
    private JwtUtil jwtUtil = new JwtUtil();


    // Lấy token từ header Authorization
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = getJwtFromRequest(request);
        if (token != null && jwtUtil.validateToken(token, jwtUtil.extractUsername(token))) {
            Claims claims = jwtUtil.extractClaims(token);
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(claims.getSubject(), null, new ArrayList<>()));
        }
        filterChain.doFilter(request, response);
    }
}
