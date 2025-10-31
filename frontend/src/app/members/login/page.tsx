"use client";

import WithLogout from "@/global/auth/hoc/withLogout";
import { useAuthContext } from "@/global/auth/hooks/useAuth";
import { fetchApi } from "@/lib/client";
import { useRouter } from "next/navigation";

export default WithLogout(function Home() {
  const { setLoginMember } = useAuthContext();
  const router = useRouter();

  const handleSubmit = (e: any) => {
    e.preventDefault();

    const form = e.target;

    const loginIdInput = form.loginId;
    const loginPwInput = form.loginPw;

    if (loginIdInput.value.length === 0) {
      alert("아이디를 입력해주세요.");
      loginIdInput.focus();
    }

    if (loginPwInput.value.length === 0) {
      alert("비밀번호 입력해주세요.");
      loginPwInput.focus();
    }

    fetchApi(`/api/v1/members/login`, {
      method: "POST",
      body: JSON.stringify({
        username: loginIdInput.value,
        password: loginPwInput.value,
      }),
    })
      .then((data) => {
        setLoginMember(data.data.memberDto);
        alert(data.msg);
        router.replace("/");
      })
      .catch((rsData) => {
        alert(rsData.msg);
      });
  };

  return (
    <>
      <h1 className="text-center">로그인</h1>
      <form className="flex flex-col gap-2 p-2" onSubmit={handleSubmit}>
        <input
          className="border border-gray-300 rounded p-2"
          type="text"
          name="loginId"
          placeholder="아이디"
          maxLength={10}
        />
        <input
          type="password"
          className="border border-gray-300 rounded p-2"
          name="loginPw"
          placeholder="비밀번호"
          maxLength={100}
        />
        <button className="bg-blue-500 text-white p-2 rounded" type="submit">
          로그인
        </button>
      </form>
    </>
  );
});
