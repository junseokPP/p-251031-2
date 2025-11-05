package com.back.global.rq

import com.back.domain.member.member.entity.Member
import com.back.global.exception.ServiceException
import com.back.global.security.SecurityUser
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import lombok.RequiredArgsConstructor
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component

@Component
@RequiredArgsConstructor
class Rq(
    private val request: HttpServletRequest,
    private val response: HttpServletResponse
) {

    val actor: Member
        get() = SecurityContextHolder
            .getContext()
            ?.authentication
            ?.principal
            ?.let {
                if (it is SecurityUser) {
                    Member(it.id, it.username, it.nickname)
                } else {
                    null
                }
            } ?: throw ServiceException(
            "401-1",
            "로그인 후 이용해주세요."
        )

    fun setHeader(name: String, value: String?) = response.setHeader(name, value)

    fun getHeader(name: String, defaultValue: String): String = request.getHeader(name) ?: defaultValue

    fun getCookieValue(name: String, defaultValue: String): String = request
        .cookies
        ?.firstOrNull { it.name == name }
        ?.value
        ?.takeIf { it.isNotBlank() }
        ?: defaultValue

    fun setCookie(name: String, value: String?) =
        Cookie(name, value ?: "")
            .apply {
                path = "/"
                isHttpOnly = true
                domain = "localhost"
                secure = true
                setAttribute("SameSite", "Strict")

                if (value.isNullOrBlank()) {
                    maxAge = 0
                }
            }
            .also {
                response.addCookie(it)
            }

    fun deleteCookie(name: String) = setCookie(name, null)

    fun sendRedirect(url: String) = response.sendRedirect(url)

}