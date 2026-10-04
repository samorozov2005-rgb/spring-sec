package ru.homework.security.task;

import jakarta.validation.constraints.NotBlank;

public record TaskRequest(@NotBlank String title, String description) {
}
