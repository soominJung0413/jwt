package com.example.jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class UserDTO {

    @NotNull
    @Size(min = 3, max = 50)
    private String username;

    @NotNull
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Size(min = 3, max = 50)
    private String password;

    @NotNull
    @Size(min = 3, max = 50)
    private String nickname;
}
