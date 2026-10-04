package ru.homework.security.security;

import org.junit.jupiter.api.Test;
import ru.homework.security.user.Role;
import ru.homework.security.user.User;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {
    private static final String SECRET =
            "c3ByaW5nLXNlY3VyaXR5LWhvbWV3b3JrLXRlc3Qtc2VjcmV0LTIwMjY=";

    @Test
    void generatedTokenContainsUsernameAndIsValid() {
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JwtService service = new JwtService(SECRET, 86_400_000, clock);
        User user = new User("user@example.com", "encoded", Role.ROLE_USER);

        String token = service.generateToken(user);

        assertThat(service.extractUsername(token)).isEqualTo(user.getEmail());
        assertThat(service.isTokenValid(token, user)).isTrue();
    }
}
