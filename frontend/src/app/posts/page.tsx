"use client";

import { fetchApi } from "@/lib/client";
import { PostDto } from "@/type/post";
import Link from "next/link";
import { useEffect, useState } from "react";

export default function Home() {
  const [posts, setPosts] = useState<PostDto[] | null>(null);

  useEffect(() => {
    fetchApi(`/api/v1/posts`).then(setPosts);
  }, []);

  return (
    <>
      <div className="flex flex-col gap-9">
        <h1>글 목록</h1>
        {posts === null && <div>Loading...</div>}
        {posts !== null && posts.length === 0 && <div>글이 없습니다.</div>}
        {posts !== null && posts.length > 0 && (
          <ul>
            {posts.map((post) => (
              <li key={post.id}>
                <Link href={`/posts/${post.id}`}>
                  {post.id} : {post.title}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div>
        <Link href="/posts/write">새 글 작성</Link>
      </div>
    </>
  );
}
