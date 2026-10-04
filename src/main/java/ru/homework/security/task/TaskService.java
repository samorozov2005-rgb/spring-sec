package ru.homework.security.task;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.homework.security.common.NotFoundException;
import ru.homework.security.user.Role;
import ru.homework.security.user.User;

import java.util.List;

@Service
@Transactional(readOnly = true)
public class TaskService {
    private final TaskRepository taskRepository;

    public TaskService(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public List<TaskResponse> getAll() {
        return taskRepository.findAll().stream().map(TaskResponse::from).toList();
    }

    public List<TaskResponse> getMyTasks(User user) {
        return taskRepository.findAllByOwnerId(user.getId()).stream().map(TaskResponse::from).toList();
    }

    @Transactional
    public TaskResponse create(TaskRequest request, User user) {
        return TaskResponse.from(taskRepository.save(new Task(request.title(), request.description(), user)));
    }

    @Transactional
    public void delete(long id, User currentUser) {
        Task task = taskRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Task not found"));
        boolean admin = currentUser.getRole() == Role.ROLE_ADMIN;
        boolean owner = task.getOwner().getId().equals(currentUser.getId());
        if (!admin && !owner) {
            throw new AccessDeniedException("Not your task");
        }
        taskRepository.delete(task);
    }
}
