export function fetchApi(url: string, options?: RequestInit) {
  options = options || {};
  options.credentials = "include";

  if (options?.body) {
    const headers = new Headers(options.headers || {});
    headers.set("Content-Type", "application/json");
    options.headers = headers;
  }

  return fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}${url}`, options).then(
    async (res) => {
      if (!res.ok) {
        const rsData = await res.json();
        throw rsData;
      }
      return res.json();
    }
  );
}
