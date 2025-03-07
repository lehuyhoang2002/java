package com.example.dreambackend.services.anh;

import com.example.dreambackend.entities.Anh;
import com.example.dreambackend.entities.SanPham;
import com.example.dreambackend.repositories.AnhRepository;
import com.example.dreambackend.repositories.SanPhamRepository;
import com.example.dreambackend.responses.AnhRespone;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Service
public class AnhService implements IAnhService {

    @Autowired
    SanPhamRepository sanPhamRepository;

    @Autowired
    AnhRepository anhRepository;

    @Override
    public List<AnhRespone> getAllAnh(Integer idSanPham) {
        return anhRepository.getAllAnhRespones(idSanPham);
    }

    @Override
    public void deleteAnh(Integer id) {
        Anh anh = anhRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy ảnh với ID: " + id));
        // Xóa file ảnh khỏi thư mục
        Path filePath = Paths.get("uploads/images/", anh.getAnhUrl().replaceFirst("/", ""));
        try {
            Files.deleteIfExists(filePath);
        } catch (IOException e) {
            throw new RuntimeException("Lỗi khi xóa file ảnh: " + e.getMessage());
        }
        anhRepository.deleteById(id);
    }

    @Override
    public List<Anh> addAnhs(List<MultipartFile> anhUrls, Integer idSanPham) {
        List<Anh> anhs = new ArrayList<>();

        try {
            // Kiểm tra sản phẩm tồn tại
            SanPham sanPham = sanPhamRepository.findById(idSanPham)
                    .orElseThrow(() -> new RuntimeException("Không tìm thấy sản phẩm với ID: " + idSanPham));

            // Lấy danh sách ảnh hiện có của sản phẩm
            List<Anh> existingAnhs = anhRepository.findBySanPhamId(idSanPham);

            // Kiểm tra số lượng ảnh không vượt quá 5
            if (existingAnhs.size() + anhUrls.size() > 5) {
                throw new RuntimeException("Mỗi sản phẩm chỉ được có tối đa 5 ảnh.");
            }
            for (MultipartFile anhUrl : anhUrls) {
                // Lưu file ảnh vào thư mục
                String uploadDir = "uploads/images/";
                String fileName = System.currentTimeMillis() + "_" + anhUrl.getOriginalFilename();
                Path filePath = Paths.get(uploadDir, fileName);
                Files.createDirectories(filePath.getParent());
                Files.write(filePath, anhUrl.getBytes());

                // Tạo đối tượng Anh
                Anh anh = new Anh();
                anh.setAnhUrl("/" + uploadDir + fileName); // URL lưu file
                anh.setSanPham(sanPham);
                anh.setNgayTao(LocalDate.now());
                anh.setNgaySua(LocalDate.now());
                anh.setTrangThai(1);

                // Lưu vào cơ sở dữ liệu
                anhs.add(anhRepository.save(anh));
            }

            return anhs;

        } catch (IOException e) {
            throw new RuntimeException("Lỗi khi lưu file ảnh: " + e.getMessage());
        }
    }


}
