package com.example.dreambackend.services.anh;

import com.example.dreambackend.entities.Anh;
import com.example.dreambackend.responses.AnhRespone;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface IAnhService {
    List<AnhRespone> getAllAnh(Integer idSanPham);

    void deleteAnh(Integer id);

    List<Anh> addAnhs(List<MultipartFile> anhUrls, Integer idSanPham);

}
