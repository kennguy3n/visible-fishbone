// Axios mutator used by every orval-generated operation.
//
// orval calls `sngRequest(config)` with the method/url/params/data for a
// given endpoint; this wrapper centralises the base URL, bearer-token
// injection, and 401 handling so the generated code stays declarative.

import axios, {
  type AxiosError,
  type AxiosRequestConfig,
  type AxiosResponse,
} from "axios";
import { runtimeConfig } from "@/lib/runtime-config";
import { clearAccessToken, getAccessToken } from "@/auth/token-store";

const instance = axios.create();

instance.interceptors.request.use((config) => {
  config.baseURL = runtimeConfig().apiBaseUrl;
  const token = getAccessToken();
  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  return config;
});

/** Dispatched when any request comes back 401 so the app can redirect. */
export const UNAUTHORIZED_EVENT = "sng:unauthorized";

instance.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      clearAccessToken();
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
      }
    }
    return Promise.reject(error);
  },
);

export const sngRequest = <T>(
  config: AxiosRequestConfig,
  options?: AxiosRequestConfig,
): Promise<T> =>
  // Cancellation flows through the AbortSignal that TanStack Query v5 passes
  // into the orval-generated request config (`config.signal`); axios aborts
  // on it natively. We deliberately avoid the deprecated `CancelToken` here.
  instance({
    ...config,
    ...options,
  }).then(({ data }: AxiosResponse<T>) => data);

export default sngRequest;
