package com.back.global.rsData

import com.fasterxml.jackson.annotation.JsonIgnore
import lombok.AllArgsConstructor
import lombok.Getter

@AllArgsConstructor
@Getter
class RsData<T> @JvmOverloads constructor
    (val resultCode: String,
     val msg: String,
     val data: T? = null) {




    @get:JsonIgnore
    val statusCode: Int
        get() {
            val statusCode =
                resultCode.split("-".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()[0]
            return statusCode.toInt()
        }
}
