"use client";

import { useAuthContext } from "@/global/auth/hooks/useAuth";
import { MemberDto } from "@/type/member";

export default function WithLogout<P extends Object>(
  Component: React.ComponentType<P & { loginMember: MemberDto }>
) {
  return function WithLogoutComponent(props: any) {
    const { isLogin } = useAuthContext();

    if (isLogin) {
      return <div>이미 로그인 되어있습니다.</div>;
    }

    return <Component {...props} />;
  };
}
