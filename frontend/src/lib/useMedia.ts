import { useCallback, useSyncExternalStore } from "react";

// True while the media query matches; follows window resizes and phone rotation.
export function useMedia(query: string): boolean {
  const subscribe = useCallback((notify: () => void) => {
    const mq = matchMedia(query);
    mq.addEventListener("change", notify);
    return () => mq.removeEventListener("change", notify);
  }, [query]);
  return useSyncExternalStore(subscribe, () => matchMedia(query).matches, () => false);
}
