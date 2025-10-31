"use client";

import WithLogin from "@/global/auth/hoc/withLogin";
import { MemberDto } from "@/type/member";

export default WithLogin(function Home({
  loginMember,
}: {
  loginMember: MemberDto;
}) {
  return (
    <>
      <h1>회원 정보</h1>
      <div>
        <div>회원번호 : {loginMember.id}</div>
        <div>이름 : {loginMember.name}</div>
        <div>가입일 : {loginMember.createDate}</div>
        <div>수정일 : {loginMember.modifyDate}</div>
      </div>
    </>
  );
});
