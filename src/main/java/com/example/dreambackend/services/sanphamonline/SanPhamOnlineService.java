package com.example.dreambackend.services.sanphamonline;

import com.example.dreambackend.dtos.SanPhamDto;
import com.example.dreambackend.repositories.SanPhamOnlineRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public class SanPhamOnlineService implements ISanPhamOnlineService {
    @Autowired
    SanPhamOnlineRepository sanPhamOnlineRepository;
    @Override
    public Page<SanPhamDto> getSanPhamOnline(Pageable pageable) {
        return sanPhamOnlineRepository.getSanPhamChiTietOnline(pageable);
    }
    @Override
    public Page<SanPhamDto> timKiemSanPham(String ten, Pageable pageable) {
        return sanPhamOnlineRepository.searchSanPhamByTen(ten, pageable);
    }
}
