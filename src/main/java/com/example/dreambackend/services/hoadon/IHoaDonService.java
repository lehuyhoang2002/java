package com.example.dreambackend.services.hoadon;

import com.example.dreambackend.entities.HoaDon;
import com.example.dreambackend.requests.HoaDonRequest;
import com.example.dreambackend.responses.HoaDonResponse;

import java.util.List;

public interface IHoaDonService {
    HoaDonResponse updateHoaDon(Integer id, HoaDonRequest request);
    HoaDonResponse createHoaDon(HoaDonRequest request);
//    void deleteHoaDon(Integer id);
    HoaDonResponse findById(Integer id);
    List<HoaDonResponse> getAllHoaDon();
}
