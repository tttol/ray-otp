import {
  Action,
  ActionPanel,
  Alert,
  Clipboard,
  confirmAlert,
  environment,
  Form,
  Icon,
  Keyboard,
  List,
  showToast,
  Toast,
} from "@raycast/api";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactElement,
} from "react";
import { iconLabel, resolveAccountIcon } from "./icons";
import {
  generateTotp,
  getRemainingSeconds,
  normalizeBase32Secret,
  validatePeriod,
} from "./totp";
import { VaultError, VaultStore, type OpenVault } from "./vault";
import type { IconStore } from "./ports";
import { cleanupAccountIcon } from "./account-icons";
import { MacKeychainStore, KeychainError } from "./keychain";
import { SessionGuard } from "./session";
import type { AccountIcon, HashAlgorithm, OtpAccount } from "./types";

type Screen = "loading" | "migration" | "locked" | "ready" | "error";
type FormValues = Record<string, Form.Value>;
type AccountFormMode = "add" | "edit";

export default function Command(): ReactElement {
  const [store] = useState(
    () =>
      new VaultStore(
        new MacKeychainStore(join(environment.assetsPath, "keychain-helper")),
      ),
  );
  const [guard] = useState(() => new SessionGuard());
  const [screen, setScreen] = useState<Screen>("loading");
  const [errorMessage, setErrorMessage] = useState<string>();
  const [accounts, setAccounts] = useState<readonly OtpAccount[]>([]);
  const [now, setNow] = useState(Date.now());
  const [form, setForm] = useState<{ readonly existing?: OtpAccount }>();
  const active = useRef<OpenVault | undefined>(undefined);
  const opening = useRef<number | undefined>(undefined);
  const saving = useRef(false);

  const lock = useCallback((): void => {
    guard.lock();
    active.current = undefined;
    setAccounts([]);
    setForm(undefined);
    setScreen("locked");
  }, [guard]);

  const activity = useCallback((): boolean => {
    if (!guard.touch()) {
      lock();
      return false;
    }
    return true;
  }, [guard, lock]);

  const openVault = useCallback(
    async (password?: string): Promise<void> => {
      if (opening.current !== undefined) return;
      const token = guard.token;
      opening.current = token;
      setScreen("loading");
      setErrorMessage(undefined);
      try {
        const status = await store.status();
        if (!guard.current(token)) return;
        if (status === "legacy" && password === undefined) {
          setScreen("migration");
          return;
        }
        const result =
          status === "missing"
            ? await store.create()
            : status === "legacy"
              ? await store.migrate(password ?? "")
              : await store.unlock();
        if (!guard.current(token)) {
          result.session.lock();
          return;
        }
        guard.open(result.session);
        active.current = result;
        setAccounts(result.data.accounts);
        setNow(Date.now());
        setScreen("ready");
      } catch (error) {
        if (guard.current(token)) {
          setErrorMessage(
            safeVaultErrorMessage(error, "Could not open the local vault"),
          );
          setScreen(password === undefined ? "error" : "migration");
        }
      } finally {
        if (opening.current === token) opening.current = undefined;
      }
    },
    [guard, store],
  );

  useEffect(() => {
    void openVault();
    return () => {
      guard.lock();
      active.current = undefined;
      opening.current = undefined;
    };
  }, [guard, openVault]);

  useEffect(() => {
    if (screen !== "ready") return;
    const timer = setInterval(() => {
      if (!guard.usable()) lock();
      else setNow(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, [guard, lock, screen]);

  const saveAccount = useCallback(
    async (account: OtpAccount): Promise<boolean> => {
      if (saving.current || !activity() || !active.current) return false;
      saving.current = true;
      const token = guard.token;
      const current = active.current;
      const exists = current.data.accounts.some(({ id }) => id === account.id);
      const next = exists
        ? current.data.accounts.map((item) =>
            item.id === account.id ? account : item,
          )
        : [...current.data.accounts, account];
      const data = {
        ...current.data,
        updatedAt: new Date().toISOString(),
        accounts: next,
      };
      try {
        await store.save(current.session, data);
        if (guard.usable(token)) {
          active.current = { ...current, data };
          setAccounts(next);
        } else if (guard.current(token)) lock();
        // A committed write owns its icon even if the UI locked during the commit.
        return true;
      } catch {
        if (guard.usable(token))
          await showToast({
            style: Toast.Style.Failure,
            title: "Could not save the vault",
          });
        return false;
      } finally {
        saving.current = false;
      }
    },
    [activity, guard, lock, store],
  );

  const copyAccount = async (account: OtpAccount): Promise<void> => {
    if (!activity()) return;
    const token = guard.token;
    try {
      const code = generateTotp(account.secret, Date.now(), {
        period: account.period,
        algorithm: account.algorithm,
      });
      await Clipboard.copy(code, { concealed: true });
      if (guard.usable(token))
        await showToast({ style: Toast.Style.Success, title: "Copied!" });
    } catch {
      if (guard.usable(token))
        await showToast({
          style: Toast.Style.Failure,
          title: "Could not copy the OTP code",
        });
    }
  };

  const deleteAccount = async (account: OtpAccount): Promise<void> => {
    if (!activity()) return;
    const token = guard.token;
    const confirmed = await confirmAlert({
      title: `Delete ${account.name}?`,
      message: "This removes the account from the encrypted vault.",
      primaryAction: { title: "Delete", style: Alert.ActionStyle.Destructive },
      dismissAction: { title: "Cancel", style: Alert.ActionStyle.Cancel },
    });
    if (!confirmed || !guard.usable(token) || saving.current || !active.current)
      return;
    saving.current = true;
    const current = active.current;
    const next = current.data.accounts.filter(({ id }) => id !== account.id);
    const data = {
      ...current.data,
      updatedAt: new Date().toISOString(),
      accounts: next,
    };
    try {
      await store.save(current.session, data);
      if (guard.usable(token)) {
        active.current = { ...current, data };
        setAccounts(next);
      } else if (guard.current(token)) lock();
      await store.icons.removeManagedIcon(account.icon);
    } catch {
      if (guard.usable(token))
        await showToast({
          style: Toast.Style.Failure,
          title: "Could not complete account deletion",
        });
    } finally {
      saving.current = false;
    }
  };

  if (screen === "loading") return <List isLoading navigationTitle="ray-otp" />;
  if (screen === "migration")
    return (
      <Form
        enableDrafts={false}
        navigationTitle="Migrate to Mac Keychain"
        actions={
          <SubmitAction
            title="Migrate to Mac Keychain"
            onSubmit={(values) => openVault(readString(values.masterPassword))}
          />
        }
      >
        <Form.Description
          title="One-time migration"
          text="Enter the existing master password once. Future launches unlock using Mac Keychain. An encrypted copy of the old vault will be retained."
        />
        {errorMessage && (
          <Form.Description title="Could Not Migrate" text={errorMessage} />
        )}
        <Form.PasswordField
          id="masterPassword"
          title="Existing Master Password"
          storeValue={false}
          autoFocus
        />
      </Form>
    );
  if (screen === "locked" || screen === "error")
    return (
      <List navigationTitle="ray-otp">
        <List.EmptyView
          icon={screen === "error" ? Icon.ExclamationMark : Icon.Lock}
          title={screen === "error" ? "Could Not Open Vault" : "Vault Locked"}
          description={errorMessage ?? "Unlock with your Mac's Keychain."}
          actions={
            <ActionPanel>
              <Action
                title={screen === "error" ? "Retry" : "Unlock with Keychain"}
                onAction={() => openVault()}
              />
            </ActionPanel>
          }
        />
      </List>
    );

  const token = guard.token;
  const formActivity = (): boolean => {
    if (!guard.current(token)) return false;
    return activity();
  };
  const closeForm = (): void => {
    if (guard.usable(token)) setForm(undefined);
  };
  if (form)
    return (
      <AccountForm
        key={form.existing?.id ?? "new"}
        existing={form.existing}
        mode={form.existing ? "edit" : "add"}
        iconStore={store.icons}
        onSave={async (account) =>
          guard.usable(token) ? saveAccount(account) : false
        }
        onActivity={formActivity}
        onClose={closeForm}
        onLock={lock}
      />
    );
  return (
    <OtpList
      accounts={accounts}
      now={now}
      onActivity={activity}
      onCopy={copyAccount}
      onDelete={deleteAccount}
      onLock={lock}
      onAdd={() => {
        if (activity()) setForm({});
      }}
      onEdit={(account) => {
        if (activity()) setForm({ existing: account });
      }}
    />
  );
}

function OtpList(props: {
  readonly accounts: readonly OtpAccount[];
  readonly now: number;
  readonly onCopy: (account: OtpAccount) => Promise<void>;
  readonly onDelete: (account: OtpAccount) => Promise<void>;
  readonly onLock: () => void;
  readonly onAdd: () => void;
  readonly onEdit: (account: OtpAccount) => void;
  readonly onActivity: () => boolean;
}): ReactElement {
  const addAction = useMemo(
    () => (
      <Action
        title="Add Account"
        icon={Icon.Plus}
        shortcut={Keyboard.Shortcut.Common.New}
        onAction={props.onAdd}
      />
    ),
    [props.onAdd],
  );

  return (
    <List
      navigationTitle="OTP Codes"
      searchBarPlaceholder="Search accounts"
      filtering={{ keepSectionOrder: true }}
      onSearchTextChange={props.onActivity}
      onSelectionChange={props.onActivity}
      actions={
        <ActionPanel>
          {addAction}
          <Action
            title="Lock Vault"
            icon={Icon.Lock}
            shortcut={{ modifiers: ["cmd", "shift"], key: "l" }}
            onAction={props.onLock}
          />
        </ActionPanel>
      }
    >
      {props.accounts.length === 0 ? (
        <List.EmptyView
          icon={Icon.Key}
          title="No OTP accounts"
          description="Add a provider's Base32 secret to generate its six-digit code."
          actions={<ActionPanel>{addAction}</ActionPanel>}
        />
      ) : (
        props.accounts.map((account) => {
          const code = generateTotp(account.secret, props.now, {
            period: account.period,
            algorithm: account.algorithm,
            digits: 6,
          });
          const remaining = getRemainingSeconds(props.now, account.period);
          const subtitle =
            account.label === undefined
              ? iconLabel(account.icon)
              : account.label;

          return (
            <List.Item
              key={account.id}
              id={account.id}
              icon={resolveAccountIcon(account.icon)}
              title={account.name}
              subtitle={subtitle}
              accessories={[
                { text: code, tooltip: "Current six-digit OTP code" },
                {
                  text: `${remaining}s`,
                  tooltip: "Seconds remaining in this period",
                },
              ]}
              actions={
                <ActionPanel>
                  <Action
                    title="Copy Code"
                    icon={Icon.CopyClipboard}
                    onAction={() => props.onCopy(account)}
                  />
                  <Action
                    title="Edit Account"
                    icon={Icon.Pencil}
                    shortcut={Keyboard.Shortcut.Common.Edit}
                    onAction={() => props.onEdit(account)}
                  />
                  <Action
                    title="Delete Account"
                    icon={Icon.Trash}
                    shortcut={{ modifiers: ["ctrl"], key: "x" }}
                    onAction={() => {
                      void props.onDelete(account);
                    }}
                  />
                  <Action
                    title="Lock Vault"
                    icon={Icon.Lock}
                    shortcut={{ modifiers: ["cmd", "shift"], key: "l" }}
                    onAction={props.onLock}
                  />
                </ActionPanel>
              }
            />
          );
        })
      )}
    </List>
  );
}

function AccountForm(props: {
  readonly existing?: OtpAccount;
  readonly iconStore: IconStore;
  readonly mode: AccountFormMode;
  readonly onSave: (account: OtpAccount) => Promise<boolean>;
  readonly onActivity: () => boolean;
  readonly onClose: () => void;
  readonly onLock: () => void;
}): ReactElement {
  const [isLoading, setIsLoading] = useState(false);
  const submitting = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const defaultIconKind =
    props.existing?.icon.kind === "builtin"
      ? props.existing.icon.name
      : props.existing
        ? "custom"
        : "generic";

  const onSubmit = async (values: FormValues): Promise<void> => {
    if (submitting.current || !props.onActivity()) return;
    const name = readString(values.name).trim();
    const label = readString(values.label).trim();
    const enteredSecret = readString(values.secret);
    const periodText = readString(values.period).trim();

    if (name.length === 0 || name.length > 200) {
      await showToast({
        style: Toast.Style.Failure,
        title: "Enter an account name",
      });
      return;
    }

    let secret: string;
    let importedIcon: AccountIcon | undefined;
    let persisted = false;
    submitting.current = true;
    setIsLoading(true);
    try {
      const iconKind = readIconKind(values.iconKind);
      const algorithm = readAlgorithm(values.algorithm);
      secret = normalizeBase32Secret(
        enteredSecret || props.existing?.secret || "",
      );
      const period = parsePeriod(periodText);
      const accountId = props.existing?.id ?? randomUUID();
      const icon = await resolveFormIcon(
        props,
        iconKind,
        values.customIconPath,
        accountId,
      );
      importedIcon = icon;
      const account: OtpAccount = {
        id: accountId,
        name,
        ...(label.length === 0 ? {} : { label }),
        secret,
        icon,
        period,
        algorithm,
        digits: 6,
      };

      const saved = await props.onSave(account);
      persisted = saved;
      const cleanup = await cleanupAccountIcon(
        props.iconStore,
        saved ? props.existing?.icon : icon,
        saved ? icon : props.existing?.icon,
      );
      if (cleanup === "failed" && mounted.current) {
        await showToast({
          style: Toast.Style.Failure,
          title: saved
            ? "Account saved; icon cleanup failed"
            : "Icon cleanup failed",
          message: "An unused local icon could not be removed.",
        });
      }
      if (saved) {
        props.onClose();
      }
    } catch (error) {
      const cleanup = await cleanupAccountIcon(
        props.iconStore,
        persisted ? undefined : importedIcon,
        props.existing?.icon,
      );
      if (mounted.current)
        await showToast({
          style: Toast.Style.Failure,
          title: safeVaultErrorMessage(error, "Could not save the account"),
          message:
            cleanup === "failed"
              ? "An unused local icon also could not be removed."
              : undefined,
        });
    } finally {
      submitting.current = false;
      if (mounted.current) setIsLoading(false);
    }
  };

  return (
    <Form
      enableDrafts={false}
      isLoading={isLoading}
      navigationTitle={props.mode === "add" ? "Add Account" : "Edit Account"}
      actions={
        <ActionPanel>
          <Action.SubmitForm
            title={props.mode === "add" ? "Add Account" : "Save Account"}
            onSubmit={onSubmit}
          />
          <Action
            title="Back to Codes"
            icon={Icon.ArrowLeft}
            onAction={props.onClose}
            shortcut={{ modifiers: ["cmd"], key: "[" }}
          />
          <Action
            title="Lock Vault"
            icon={Icon.Lock}
            onAction={props.onLock}
            shortcut={{ modifiers: ["cmd", "shift"], key: "l" }}
          />
        </ActionPanel>
      }
    >
      <Form.TextField
        id="name"
        onChange={props.onActivity}
        storeValue={false}
        title="Account Name"
        defaultValue={props.existing?.name}
        placeholder="AWS Production"
      />
      <Form.TextField
        id="label"
        onChange={props.onActivity}
        storeValue={false}
        title="Account Label"
        defaultValue={props.existing?.label}
        placeholder="Optional username or environment"
      />
      <Form.PasswordField
        id="secret"
        onChange={props.onActivity}
        storeValue={false}
        title={props.mode === "add" ? "Base32 Secret" : "New Secret (Optional)"}
        placeholder={
          props.mode === "add"
            ? "Enter the provider's Base32 secret"
            : "Leave blank to keep the current secret"
        }
      />
      <Form.Dropdown
        id="iconKind"
        title="Icon"
        defaultValue={defaultIconKind}
        onChange={props.onActivity}
        storeValue={false}
      >
        <Form.Dropdown.Item value="aws" title="AWS" />
        <Form.Dropdown.Item value="microsoft" title="Microsoft" />
        <Form.Dropdown.Item value="generic" title="Generic" />
        <Form.Dropdown.Item value="custom" title="Custom local image" />
      </Form.Dropdown>
      <Form.FilePicker
        id="customIconPath"
        onChange={props.onActivity}
        storeValue={false}
        title="Custom Icon"
        allowMultipleSelection={false}
        canChooseDirectories={false}
        showHiddenFiles={false}
      />
      <Form.TextField
        id="period"
        onChange={props.onActivity}
        storeValue={false}
        title="Period (seconds)"
        defaultValue={String(props.existing?.period ?? 30)}
        placeholder="30"
      />
      <Form.Dropdown
        id="algorithm"
        onChange={props.onActivity}
        storeValue={false}
        title="Algorithm"
        defaultValue={props.existing?.algorithm ?? "sha1"}
      >
        <Form.Dropdown.Item value="sha1" title="SHA-1" />
        <Form.Dropdown.Item value="sha256" title="SHA-256" />
        <Form.Dropdown.Item value="sha512" title="SHA-512" />
      </Form.Dropdown>
      <Form.Description
        title="Security"
        text="The secret is encrypted locally and is never sent to a provider or remote service."
      />
    </Form>
  );
}

function SubmitAction(props: {
  readonly title: string;
  readonly onSubmit: (values: FormValues) => Promise<void>;
}): ReactElement {
  return (
    <ActionPanel>
      <Action.SubmitForm title={props.title} onSubmit={props.onSubmit} />
    </ActionPanel>
  );
}

async function resolveFormIcon(
  props: { readonly existing?: OtpAccount; readonly iconStore: IconStore },
  iconKind: BuiltinFormIcon,
  value: Form.Value | undefined,
  accountId: string,
): Promise<AccountIcon> {
  if (iconKind !== "custom") {
    return { kind: "builtin", name: iconKind };
  }

  const selectedPath = readFilePickerPath(value);
  if (selectedPath !== undefined) {
    return {
      kind: "custom",
      path: await props.iconStore.importIcon(selectedPath, accountId),
    };
  }

  if (props.existing?.icon.kind === "custom") {
    return props.existing.icon;
  }

  throw new VaultError("Choose a PNG or JPEG file for a custom icon.");
}

type BuiltinFormIcon = "aws" | "microsoft" | "generic" | "custom";

function readIconKind(value: Form.Value | undefined): BuiltinFormIcon {
  const candidate = readString(value);
  if (
    candidate === "aws" ||
    candidate === "microsoft" ||
    candidate === "generic" ||
    candidate === "custom"
  ) {
    return candidate;
  }
  throw new VaultError("Choose a valid icon.");
}

function readAlgorithm(value: Form.Value | undefined): HashAlgorithm {
  const candidate = readString(value);
  if (
    candidate === "sha1" ||
    candidate === "sha256" ||
    candidate === "sha512"
  ) {
    return candidate;
  }
  throw new VaultError("Choose a valid hash algorithm.");
}

function parsePeriod(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new VaultError("The period must be a whole number of seconds.");
  }
  const period = Number(value);
  return validatePeriod(period);
}

function readString(value: Form.Value | undefined): string {
  return typeof value === "string" ? value : "";
}

function readFilePickerPath(value: Form.Value | undefined): string | undefined {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }

  if (Array.isArray(value)) {
    const first = value[0];
    return typeof first === "string" && first.length > 0 ? first : undefined;
  }

  return undefined;
}

function safeVaultErrorMessage(error: unknown, fallback: string): string {
  return error instanceof VaultError || error instanceof KeychainError
    ? error.message
    : fallback;
}
