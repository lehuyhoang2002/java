package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.ThuongHieu;
import com.example.dreambackend.responses.ThuongHieuRespone;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ThuongHieuRepository extends JpaRepository<ThuongHieu, Integer> {
    @Query("""
    select new com.example.dreambackend.responses.ThuongHieuRespone(
        th.id,
        th.ma,
        th.ten,
        th.ngayTao,
        th.ngaySua,
        th.trangThai
        )from ThuongHieu th
        """)
    List<ThuongHieuRespone> getAllThuongHieuRespones();

    boolean existsByMa(String ma);

    boolean existsByTen(String ten);
}
