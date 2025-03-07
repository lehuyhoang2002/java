package com.example.dreambackend.services.vaitro;

import com.example.dreambackend.entities.VaiTro;
import com.example.dreambackend.repositories.VaiTroRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VaiTroService implements IVaiTroService {

    @Autowired
    private VaiTroRepository vaiTroRepository;

    @Transactional
    @Override
    public List<VaiTro> getAllVaiTros() {
        return vaiTroRepository.findAll();
    }

    @Transactional
    @Override
    public VaiTro addVaiTro(VaiTro vaiTro) {
        return vaiTroRepository.save(vaiTro);
    }

    @Transactional
    @Override
    public VaiTro updateVaiTro(VaiTro vaiTro) {
        return vaiTroRepository.save(vaiTro);
    }
}
