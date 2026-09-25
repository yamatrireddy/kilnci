// SPDX-License-Identifier: Apache-2.0
import { useCallback, useState } from "react";

export interface DisclosureHandlers {
  open: () => void;
  close: () => void;
  toggle: () => void;
}

/** Open/closed state for modals, menus, and the mobile navigation. */
export function useDisclosure(initial = false): [boolean, DisclosureHandlers] {
  const [opened, setOpened] = useState(initial);
  const open = useCallback(() => {
    setOpened(true);
  }, []);
  const close = useCallback(() => {
    setOpened(false);
  }, []);
  const toggle = useCallback(() => {
    setOpened((o) => !o);
  }, []);
  return [opened, { open, close, toggle }];
}
