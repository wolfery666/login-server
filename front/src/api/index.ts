import router from '@/router'
import authState from '@/state/auth'

type RequestOptions = Omit<RequestInit, 'body'> & { body?: RequestInit['body'] | object }

export const apiFetch = async (url: string, options: RequestOptions = {}): Promise<Response> => {
  const headers = new Headers(options.headers)
  const credentials = options.credentials || 'include'
  let body = options.body

  if (
    body &&
    typeof body === 'object' &&
    !(body instanceof FormData) &&
    !(body instanceof Blob) &&
    !(body instanceof ArrayBuffer)
  ) {
    body = JSON.stringify(body)
    headers.set('Content-Type', 'application/json')
  }

  const res = await fetch(`/api${url}`, { ...options, credentials, headers, body })

  if (res.status === 401) {
    authState.loggedIn = false
  }
  
  return res
}
