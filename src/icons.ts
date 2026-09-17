import { environment } from "@raycast/api";
import { basename, join } from "node:path";
import type { AccountIcon } from "./types";

export function resolveAccountIcon(icon: AccountIcon): string {
  if (icon.kind === "custom") {
    return icon.path;
  }

  return join(environment.assetsPath, `${icon.name}.svg`);
}

export function iconLabel(icon: AccountIcon): string {
  if (icon.kind === "builtin") {
    return icon.name === "aws"
      ? "AWS"
      : icon.name === "microsoft"
        ? "Microsoft"
        : "Generic";
  }

  return basename(icon.path);
}
