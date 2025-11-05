package com.back.domain.post.comment.dto

import com.back.domain.post.comment.entity.Comment
import java.time.LocalDateTime

@JvmRecord
data class CommentDto private constructor(
    val id: Long,
    val createDate: LocalDateTime,
    val modifyDate: LocalDateTime,
    val content: String,
    val authorId: Long,
    val authorName: String,
    val postId: Long
) {
    constructor(comment: Comment) : this(
        comment.id,
        comment.createDate,
        comment.modifyDate,
        comment.content,
        comment.author.id,
        comment.author.name,
        comment.post.id
    )
}