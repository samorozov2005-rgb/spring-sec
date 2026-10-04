package ru.homework.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import ru.homework.security.auth.RefreshToken;
import ru.homework.security.auth.RefreshTokenRepository;
import ru.homework.security.task.TaskRepository;
import ru.homework.security.user.Role;
import ru.homework.security.user.User;
import ru.homework.security.user.UserRepository;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowIntegrationTest {
    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private TaskRepository taskRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @BeforeEach
    void cleanDatabase() {
        refreshTokenRepository.deleteAll();
        taskRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void register_login_protectedGet_shouldReturn200() throws Exception {
        register("flow@example.com", "password123");
        String accessToken = login("flow@example.com", "password123").get("accessToken").asText();

        mockMvc.perform(get("/tasks").header("Authorization", bearer(accessToken)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    @Test
    void userDeletingAnotherUsersTask_shouldReturn403() throws Exception {
        JsonNode first = register("first@example.com", "password123");
        JsonNode second = register("second@example.com", "password123");
        long taskId = createTask(second.get("accessToken").asText(), "Second user's task");

        mockMvc.perform(delete("/tasks/{id}", taskId)
                        .header("Authorization", bearer(first.get("accessToken").asText())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Not your task"));

        assertThat(taskRepository.existsById(taskId)).isTrue();
    }

    @Test
    void register_withDuplicateEmail_shouldReturn409() throws Exception {
        register("duplicate@example.com", "password123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials("duplicate@example.com", "password123")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Email already registered"));

        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    void register_withShortPassword_shouldReturn400() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials("valid@example.com", "short")))
                .andExpect(status().isBadRequest());
        assertThat(userRepository.count()).isZero();
    }

    @Test
    void register_withInvalidEmail_shouldReturn400() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials("not-an-email", "password123")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getMyTasks_shouldReturnOnlyCurrentUsersTasks() throws Exception {
        JsonNode first = register("owner@example.com", "password123");
        JsonNode second = register("other@example.com", "password123");
        createTask(first.get("accessToken").asText(), "Mine");
        createTask(second.get("accessToken").asText(), "Not mine");

        mockMvc.perform(get("/tasks/my")
                        .header("Authorization", bearer(first.get("accessToken").asText())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].title").value("Mine"))
                .andExpect(jsonPath("$[0].ownerEmail").value("owner@example.com"));
    }

    @Test
    void refresh_withValidToken_shouldReturn200_andRotateToken() throws Exception {
        JsonNode login = register("refresh@example.com", "password123");
        String oldRefreshToken = login.get("refreshToken").asText();

        String body = mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(oldRefreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        String newRefreshToken = objectMapper.readTree(body).get("refreshToken").asText();
        assertThat(newRefreshToken).isNotEqualTo(oldRefreshToken);
        assertThat(refreshTokenRepository.findByToken(oldRefreshToken)).isEmpty();
        assertThat(refreshTokenRepository.findByToken(newRefreshToken)).isPresent();

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(oldRefreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_withExpiredToken_shouldReturn401() throws Exception {
        User user = userRepository.save(new User(
                "expired@example.com", passwordEncoder.encode("password123"), Role.ROLE_USER));
        refreshTokenRepository.save(new RefreshToken(
                "expired-refresh-token", user, LocalDateTime.now(ZoneOffset.UTC).minusMinutes(1)));

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody("expired-refresh-token")))
                .andExpect(status().isUnauthorized());

    }

    @Test
    void refresh_withUnknownToken_shouldReturn401() throws Exception {
        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody("unknown-refresh-token")))
                .andExpect(status().isUnauthorized());
    }

    private JsonNode register(String email, String password) throws Exception {
        String body = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(email, password)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body);
    }

    private JsonNode login(String email, String password) throws Exception {
        String body = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(email, password)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body);
    }

    private long createTask(String accessToken, String title) throws Exception {
        String body = mockMvc.perform(post("/tasks")
                        .header("Authorization", bearer(accessToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TaskJson(title, "description"))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asLong();
    }

    private String credentials(String email, String password) throws Exception {
        return objectMapper.writeValueAsString(new Credentials(email, password));
    }

    private String refreshBody(String refreshToken) throws Exception {
        return objectMapper.writeValueAsString(new RefreshJson(refreshToken));
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private record Credentials(String email, String password) { }
    private record RefreshJson(String refreshToken) { }
    private record TaskJson(String title, String description) { }
}
