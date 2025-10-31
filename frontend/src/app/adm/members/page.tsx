"use client";

import WithAdmin from "@/global/auth/hoc/withAdmin";
import { fetchApi } from "@/lib/client";
import { MemberWithUsernameDto } from "@/type/member";
import Link from "next/link";
import { useEffect, useState } from "react";

export default WithAdmin(function Home({ isAdmin }: { isAdmin: boolean }) {
  const [members, setMembers] = useState<MemberWithUsernameDto[] | null>(null);

  useEffect(() => {
    if (!isAdmin) {
      return;
    }

    fetchApi(`/api/v1/adm/members`)
      .then(setMembers)
      .catch((rsData) => {
        alert(rsData.msg);
      });
  }, []);

  return (
    <>
      <div className="flex flex-col gap-9">
        <h1>회원 목록</h1>
        {members === null && <div>Loading...</div>}
        {members !== null && members.length === 0 && (
          <div>회원이 없습니다.</div>
        )}
        {members !== null && members.length > 0 && (
          <ul>
            {members.map((member) => (
              <li key={member.id}>
                <Link href={`/posts/${member.id}`}>
                  {member.id} : {member.username} / {member.nickname}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
});
