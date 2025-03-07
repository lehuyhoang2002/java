package com.example.dreambackend.services.sanphamonline;

import com.example.dreambackend.dtos.SanPhamDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface ISanPhamOnlineService {
    Page<SanPhamDto> getSanPhamOnline(Pageable pageable);
    Page<SanPhamDto> timKiemSanPham (String ten,Pageable pageable);
}
