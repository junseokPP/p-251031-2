"use client";
import { useAuthContext } from "@/global/auth/hooks/useAuth";
import { MemberDto } from "@/type/member";

export default function WithLogin<P extends Object>(
  Component: React.ComponentType<P & { loginMember: MemberDto }>
) {
  return function WithLoginComponent(props: any) {
    const { isLogin, loginMember } = useAuthContext();

    if (!isLogin) {
      return <div>로그인 후 이용해주세요.</div>;
    }

    return <Component {...props} loginMember={loginMember} />;
  };
}
