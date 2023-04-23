package com.luxoft.spingsecurity.basicauth.service;

import com.luxoft.spingsecurity.basicauth.dto.UserDto;
import com.luxoft.spingsecurity.basicauth.dto.converters.UserDtoConverter;
import com.luxoft.spingsecurity.basicauth.repository.UserRepository;
import com.luxoft.spingsecurity.basicauth.security.CurrentUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static java.util.stream.Collectors.toList;

@Service
@RequiredArgsConstructor
public class UserService {

    private final CurrentUserService currentUserService;
    private final UserRepository userRepository;
    private final UserDtoConverter userDtoConverter;

    public UserDto getCurrentUser() {
        return userDtoConverter.toDto(currentUserService.getCurrentUser());
    }

    @Transactional(readOnly = true)
    public List<UserDto> getAll() {
        return userRepository.findAll().stream()
            .map(userDtoConverter::toDto)
            .collect(toList());
    }

    @Transactional(readOnly = true)
    public UserDto getById(long userId) {
        return userRepository.findById(userId)
            .map(userDtoConverter::toDto)
            .orElseThrow(() -> new IllegalArgumentException("User does not exist"));
    }

    @Transactional
    public UserDto create(UserDto userDto) {
        var user = userDtoConverter.toDomain(userDto);
        var withId = userRepository.save(user);
        return userDtoConverter.toDto(withId);
    }

    @Transactional
    public UserDto update(UserDto userDto) {
        var user = userRepository.findById(userDto.getId())
            .orElseThrow(() -> new IllegalArgumentException("User does not exist"));
        var updated = userDtoConverter.toDomain(userDto, user);
        var fromDb = userRepository.save(updated);
        return userDtoConverter.toDto(fromDb);
    }
}
