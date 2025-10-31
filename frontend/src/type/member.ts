export type MemberDto = {
  id: number;
  name: string;
  createDate: string;
  modifyDate: string;
  isAdmin: boolean;
};

export type MemberWithUsernameDto = MemberDto & {
  username: string;
  nickname: string;
};
