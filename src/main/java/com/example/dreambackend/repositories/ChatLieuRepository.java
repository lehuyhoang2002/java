package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.ChatLieu;
import com.example.dreambackend.responses.ChatLieuRespone;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ChatLieuRepository extends JpaRepository<ChatLieu, Integer> {
    @Query("""
    select new com.example.dreambackend.responses.ChatLieuRespone(
        cl.id,
        cl.ma,
        cl.ten,
        cl.ngayTao,
        cl.ngaySua,
        cl.trangThai
        ) from ChatLieu cl
        """)
    List<ChatLieuRespone> getAllChatLieuRepone();

    boolean existsByMa(String ma);

    boolean existsByTen(String ten);
}
