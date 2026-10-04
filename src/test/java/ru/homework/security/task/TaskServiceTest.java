package ru.homework.security.task;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import ru.homework.security.user.Role;
import ru.homework.security.user.User;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TaskServiceTest {
    @Mock
    private TaskRepository taskRepository;
    private TaskService taskService;
    private User user1;
    private User user2;
    private Task task;

    @BeforeEach
    void setUp() {
        taskService = new TaskService(taskRepository);
        user1 = user("user1@example.com", Role.ROLE_USER);
        user2 = user("user2@example.com", Role.ROLE_USER);
        task = new Task("Task", null, user1);
        task.setId(1L);
        when(taskRepository.findById(1L)).thenReturn(Optional.of(task));
    }

    @Test
    void userCannotDeleteAnotherUsersTask() {
        assertThatThrownBy(() -> taskService.delete(1L, user2))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Not your task");
        verify(taskRepository, never()).delete(any());
    }

    @Test
    void adminCanDeleteAnotherUsersTask() {
        User admin = user("admin@example.com", Role.ROLE_ADMIN);

        taskService.delete(1L, admin);

        verify(taskRepository).delete(task);
    }

    @Test
    void userCanDeleteOwnTask() {
        taskService.delete(1L, user1);

        verify(taskRepository).delete(task);
    }

    private static User user(String email, Role role) {
        User user = new User(email, "encoded", role);
        user.setId(UUID.randomUUID());
        return user;
    }
}
