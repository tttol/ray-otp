import type { VaultSession } from "./vault";

/** Invalidates pending work on lock and checks deadlines before every action. */
export class SessionGuard {
  private revision = 0;
  private deadline = 0;
  private session: VaultSession | undefined;
  public constructor(
    private readonly clock: () => number = Date.now,
    private readonly timeout = 300_000,
  ) {}

  public get token(): number {
    return this.revision;
  }
  public current(token: number): boolean {
    return token === this.revision;
  }

  public open(session: VaultSession): void {
    this.lock();
    this.session = session;
    this.deadline = this.clock() + this.timeout;
  }

  public usable(token = this.revision): boolean {
    return (
      this.current(token) &&
      this.session !== undefined &&
      this.clock() < this.deadline
    );
  }

  public touch(token = this.revision): boolean {
    if (!this.usable(token)) return false;
    this.deadline = this.clock() + this.timeout;
    return true;
  }

  public lock(): void {
    this.revision += 1;
    this.session?.lock();
    this.session = undefined;
    this.deadline = 0;
  }
}
