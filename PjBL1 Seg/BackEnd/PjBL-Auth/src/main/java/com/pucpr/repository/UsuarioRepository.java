package com.pucpr.repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UsuarioRepository {
    private final String FILE_PATH = "usuarios.json";
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Busca um usuário pelo e-mail dentro do arquivo JSON.
     */
    public Optional<Usuario> findByEmail(String email) {
        // 1. Carrega a lista e usa Streams
        // 2 e 3. Filtra ignorando maiúsculas/minúsculas e pega o primeiro
        return findAll().stream()
                .filter(usuario -> usuario.getEmail().equalsIgnoreCase(email))
                .findFirst();
    }

    /**
     * Retorna todos os usuários cadastrados no arquivo JSON.
     */
    public List<Usuario> findAll() {
        File file = new File(FILE_PATH);
        
        // 1 e 2. Verifica se o arquivo existe, se não, retorna lista vazia
        if (!file.exists()) {
            return new ArrayList<>();
        }
        
        try {
            // 3. Lê o arquivo e converte para List<Usuario> usando o Jackson
            return mapper.readValue(file, new TypeReference<List<Usuario>>() {});
        } catch (IOException e) {
            // Em caso de erro na leitura do arquivo (ex: JSON mal formatado)
            System.err.println("Erro ao ler o arquivo JSON: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Salva um novo usuário no arquivo JSON.
     */
    public void save(Usuario usuario) throws IOException {
        // 1. Obtém a lista atual
        List<Usuario> usuarios = findAll();

        // 2. Verifica se o e-mail já existe (Regra de Negócio)
        // Reutilizamos o método findByEmail para não duplicar código
        if (findByEmail(usuario.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Erro: O e-mail " + usuario.getEmail() + " já está em uso.");
        }

        // 3. Adiciona o novo objeto à lista
        usuarios.add(usuario);

        // 4. Grava a lista atualizada no arquivo, formatada (PrettyPrinter)
        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(FILE_PATH), usuarios);
    }
}