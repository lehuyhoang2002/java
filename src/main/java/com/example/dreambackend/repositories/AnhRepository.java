package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.Anh;
import com.example.dreambackend.responses.AnhRespone;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AnhRepository extends JpaRepository<Anh, Integer> {
    @Query("""
    select new com.example.dreambackend.responses.AnhRespone(
        a.id,
        a.anhUrl,
        a.ngayTao,
        a.ngaySua,
        a.trangThai,
        a.sanPham.id
        ) from Anh a WHERE a.sanPham.id = :idSanPham
        """)
    List<AnhRespone> getAllAnhRespones(@Param("idSanPham") Integer idSanPham);

    List<Anh> findBySanPhamId(Integer idSanPham);
}
