package ru.homework.security.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.homework.security.common.EmailAlreadyRegisteredException;
import ru.homework.security.common.InvalidRefreshTokenException;
import ru.homework.security.security.JwtService;
import ru.homework.security.user.Role;
import ru.homework.security.user.User;
import ru.homework.security.user.UserRepository;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthService {
    private static final long REFRESH_TOKEN_DAYS = 7;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final Clock clock;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       Clock clock) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.clock = clock;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyRegisteredException();
        }
        User user;
        try {
            user = userRepository.saveAndFlush(
                    new User(request.email(), passwordEncoder.encode(request.password()), Role.ROLE_USER));
        } catch (DataIntegrityViolationException exception) {
            throw new EmailAlreadyRegisteredException();
        }
        return issueTokenPair(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password()));
        User user = userRepository.findByEmail(request.email()).orElseThrow();
        return issueTokenPair(user);
    }

    @Transactional
    public AuthResponse refresh(String rawToken) {
        RefreshToken stored = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(InvalidRefreshTokenException::new);
        if (!stored.getExpiresAt().isAfter(LocalDateTime.now(clock))) {
            throw new InvalidRefreshTokenException();
        }
        User user = stored.getUser();
        refreshTokenRepository.delete(stored);
        refreshTokenRepository.flush();
        return issueTokenPair(user);
    }

    private AuthResponse issueTokenPair(User user) {
        String refreshValue = UUID.randomUUID().toString();
        RefreshToken refreshToken = new RefreshToken(
                refreshValue, user, LocalDateTime.now(clock).plusDays(REFRESH_TOKEN_DAYS));
        refreshTokenRepository.save(refreshToken);
        return new AuthResponse(jwtService.generateToken(user), refreshValue);
    }
}
