package com.back.domain.member.member.dto;

import com.back.domain.member.member.entity.Member;

import java.time.LocalDateTime;

public record MemberDto(
        Long id,
        LocalDateTime createDate,
        LocalDateTime modifyDate,
        String name,
        boolean isAdmin
) {
    public MemberDto(Member member) {
        this(
                member.getId(),
                member.getCreateDate(),
                member.getModifyDate(),
                member.getName(),
                member.isAdmin()
        );
    }
}
