package com.back

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.data.jpa.repository.config.EnableJpaAuditing

@SpringBootApplication
@EnableJpaAuditing
object BackendApplication {
    @JvmStatic
    fun main(args: Array<String>) {
        SpringApplication.run(BackendApplication::class.java, *args)
    }
}
