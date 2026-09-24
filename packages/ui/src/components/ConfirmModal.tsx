// SPDX-License-Identifier: Apache-2.0
import { Button, Group, Modal, Text } from "@mantine/core";
import type { ReactNode } from "react";

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
    <Modal opened={opened} onClose={onClose} title={title} centered>
      <Text size="sm">{children}</Text>
      <Group justify="flex-end" mt="lg">
        <Button variant="default" onClick={onClose}>
          Cancel
        </Button>
        <Button color="red" onClick={onConfirm} loading={loading ?? false}>
          {confirmLabel}
        </Button>
      </Group>
    </Modal>
  );
}
