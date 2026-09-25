// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";

import { Button, Modal } from "./ui";

/** Confirmation for destructive actions (coding-standards §11). */
export function ConfirmModal({
  opened,
  title,
  children,
  confirmLabel,
  loading,
  onConfirm,
  onClose,
}: {
  opened: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  loading?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal opened={opened} onClose={onClose} title={title}>
      <p className="text-sm text-fg">{children}</p>
      <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button variant="default" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" onClick={onConfirm} loading={loading ?? false}>
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
