package ru.homework.security.task;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.homework.security.user.User;

import java.util.List;

@RestController
@RequestMapping("/tasks")
@PreAuthorize("isAuthenticated()")
public class TaskController {
    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @GetMapping
    public List<TaskResponse> getAll() {
        return taskService.getAll();
    }

    @GetMapping("/my")
    public List<TaskResponse> getMyTasks(@AuthenticationPrincipal User user) {
        return taskService.getMyTasks(user);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public TaskResponse create(@Valid @RequestBody TaskRequest request,
                               @AuthenticationPrincipal User user) {
        return taskService.create(request, user);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable long id, @AuthenticationPrincipal User user) {
        taskService.delete(id, user);
    }
}
