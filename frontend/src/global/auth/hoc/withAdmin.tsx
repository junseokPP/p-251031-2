"use client";
import { useAuthContext } from "@/global/auth/hooks/useAuth";

export default function WithAdmin<P extends Object>(
  Component: React.ComponentType<P & { isAdmin: boolean }>
) {
  return function WithAdminComponent(props: any) {
    const { isLogin, isAdmin } = useAuthContext();

    if (!isLogin) {
      return <div>로그인 후 이용해주세요.</div>;
    }

    if (!isAdmin) {
      return <div>관리자 권한이 없습니다.</div>;
    }

    return <Component {...props} isAdmin={isAdmin} />;
  };
}
