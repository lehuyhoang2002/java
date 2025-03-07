package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.Voucher;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface VoucherRepository extends JpaRepository<Voucher,Integer> {
    List<Voucher> findByTenContainingIgnoreCase(String ten);

}

