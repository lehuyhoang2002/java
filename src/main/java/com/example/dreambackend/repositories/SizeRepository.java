package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.Size;
import com.example.dreambackend.responses.SizeRespone;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SizeRepository extends JpaRepository<Size, Integer> {
    @Query("""
    select new com.example.dreambackend.responses.SizeRespone(
        s.id,
        s.ma,
        s.ten,
        s.ngayTao,
        s.ngaySua,
        s.trangThai
        )from Size s
        """)
    List<SizeRespone> getAllSizeRespones();

    boolean existsByMa(String ma);

    boolean existsByTen(String ten);
}
