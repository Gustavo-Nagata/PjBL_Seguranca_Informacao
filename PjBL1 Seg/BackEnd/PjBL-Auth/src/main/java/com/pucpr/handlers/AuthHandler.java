package com.pucpr.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;
import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }

    public void handleLogin(HttpExchange exchange) throws IOException {
        // Libera o CORS para a requisição de pré-checagem (Preflight)
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            adicionarCabecalhosCors(exchange);
            exchange.sendResponseHeaders(204, -1);
            exchange.close(); // <--- A LINHA MÁGICA AQUI
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            adicionarCabecalhosCors(exchange);
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        try {
            InputStream is = exchange.getRequestBody();
            Map<String, String> credenciais = mapper.readValue(is, Map.class);
            String email = credenciais.get("email");
            String senhaInformada = credenciais.containsKey("senhaHash") ? credenciais.get("senhaHash") : credenciais.get("senha");

            Optional<Usuario> usuarioOpt = repository.findByEmail(email);

            if (usuarioOpt.isEmpty() || !BCrypt.checkpw(senhaInformada, usuarioOpt.get().getSenhaHash())) {
                enviarResposta(exchange, 401, "{\"erro\": \"E-mail ou senha inválidos\"}");
                return;
            }

            Usuario usuario = usuarioOpt.get();
            String token = jwtService.generateToken(usuario);

            enviarResposta(exchange, 200, "{\"token\": \"" + token + "\"}");

        } catch (Exception e) {
            e.printStackTrace();
            enviarResposta(exchange, 500, "{\"erro\": \"Erro interno do servidor\"}");
        }
    }

    public void handleRegister(HttpExchange exchange) throws IOException {
        // Libera o CORS para a requisição de pré-checagem (Preflight)
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            adicionarCabecalhosCors(exchange);
            exchange.sendResponseHeaders(204, -1);
            exchange.close(); // <--- A LINHA MÁGICA AQUI
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            adicionarCabecalhosCors(exchange);
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        try {
            InputStream is = exchange.getRequestBody();
            Usuario novoUsuario = mapper.readValue(is, Usuario.class);

            if (repository.findByEmail(novoUsuario.getEmail()).isPresent()) {
                enviarResposta(exchange, 400, "{\"erro\": \"Este e-mail já está em uso.\"}");
                return;
            }

            String senhaPura = novoUsuario.getSenhaHash();
            String senhaHasheada = BCrypt.hashpw(senhaPura, BCrypt.gensalt(12));
            novoUsuario.setSenhaHash(senhaHasheada);

            repository.save(novoUsuario);

            enviarResposta(exchange, 201, "{\"mensagem\": \"Usuário cadastrado com sucesso!\"}");

        } catch (Exception e) {
            e.printStackTrace();
            enviarResposta(exchange, 500, "{\"erro\": \"Erro ao processar o cadastro\"}");
        }
    }

    // Reforço nos cabeçalhos para o navegador não reclamar de nada
    private void adicionarCabecalhosCors(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin, Accept");
    }

    private void enviarResposta(HttpExchange exchange, int statusCode, String jsonResponse) throws IOException {
        adicionarCabecalhosCors(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}