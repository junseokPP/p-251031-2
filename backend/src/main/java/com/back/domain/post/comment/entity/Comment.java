package com.back.domain.post.comment.entity;

import com.back.domain.member.member.entity.Member;
import com.back.domain.post.post.entity.Post;
import com.back.global.exception.ServiceException;
import com.back.global.jpa.entity.BaseEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@Entity
@AllArgsConstructor
@NoArgsConstructor
public class Comment extends BaseEntity {

    private String content;
    @ManyToOne(fetch = FetchType.LAZY)
    @JsonIgnore
    private Post post;
    @ManyToOne(fetch = FetchType.LAZY)
    private Member author;

    public Comment(Member author, String content, Post post) {
        this.author = author;
        this.content = content;
        this.post = post;
    }

    public void update(String content) {
        this.content = content;
    }

    public void checkActorModify(Member actor) {
        if(!this.author.getId().equals(actor.getId())) {
            throw new ServiceException("403-1", "댓글 수정 권한이 없습니다.");
        }
    }

    public void checkActorDelete(Member actor) {
        if(!this.author.getId().equals(actor.getId())) {
            throw new ServiceException("403-2", "댓글 삭제 권한이 없습니다.");
        }
    }

    public String getContent() {
        return content;
    }

    public Post getPost() {
        return post;
    }

    public Member getAuthor() {
        return author;
    }
}