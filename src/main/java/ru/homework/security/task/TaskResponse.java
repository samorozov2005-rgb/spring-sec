package ru.homework.security.task;

public record TaskResponse(Long id, String title, String description, String ownerEmail) {
    public static TaskResponse from(Task task) {
        return new TaskResponse(task.getId(), task.getTitle(), task.getDescription(), task.getOwner().getEmail());
    }
}
