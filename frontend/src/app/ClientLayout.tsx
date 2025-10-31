"use client";
import { useAuthContext } from "@/global/auth/hooks/useAuth";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function ClientLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const authState = useAuthContext();
  const {
    loginMember,
    getLoginMember,
    logout: _logout,
    isLogin,
    isAdmin,
  } = authState;
  const router = useRouter();

  useEffect(() => {
    getLoginMember({
      onSuccess: (data) => {
        console.log("data", data);
      },
      onError: (err) => {
        console.log("err", err);
      },
    });
  }, []);

  const logout = () => {
    _logout({
      onSuccess: (data) => {
        alert(data.msg);
        router.replace("/");
      },
      onError: (rsData) => {
        alert(rsData.msg);
      },
    });
  };

  return (
    <>
      <header>
        <nav className="flex gap-4">
          <Link href="/">메인</Link>
          <Link href="/posts">글 목록</Link>
          {!isLogin && <Link href="/members/login">로그인</Link>}
          {!isLogin && (
            <Link href="http://localhost:8080/oauth2/authorization/kakao">
              카카오 로그인
            </Link>
          )}
          {isLogin && <button onClick={logout}>로그아웃</button>}
          {isLogin && <Link href="/members/me">{loginMember?.name}</Link>}
          {isLogin && isAdmin && <Link href="/adm/members">회원 목록</Link>}
        </nav>
      </header>
      <main className="flex-1 flex flex-col justify-center items-center">
        {children}
      </main>
      <footer>푸터</footer>
    </>
  );
}
