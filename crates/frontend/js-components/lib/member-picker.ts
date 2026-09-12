import { html, LitElement } from "lit";
import { customElement, property } from "lit/decorators.js";

interface UserResult {
  id: string;
  displayname: string;
}

@customElement("member-picker")
export class MemberPicker extends LitElement {
  @property({ type: Number })
  debounce: number = 300;

  @property({ type: Array })
  suggestions: UserResult[] = [];

  @property()
  query: string = "";

  @property()
  error: string = "";

  @property()
  groupId: string = "";

  @property({ type: Boolean })
  loading: boolean = false;

  @property({ type: Boolean })
  showDropdown: boolean = false;

  @property({ type: Boolean })
  adding: boolean = false;

  private _debounceTimer: ReturnType<typeof setTimeout> | null = null;

  protected override createRenderRoot() {
    return this;
  }

  override render() {
    return html`
      ${this.error ? html`<p class="error">${this.error}</p>` : ""}
      <div class="member-picker" style="position:relative">
        <input
          type="text"
          .value=${this.query}
          @input=${this._onInput}
          @focus=${() => { if (this.suggestions.length) this.showDropdown = true; }}
          placeholder="Search users..."
          autocomplete="off"
        >
        ${this.showDropdown && this.suggestions.length > 0 ? html`
          <ul class="member-picker-dropdown" style="
            position:absolute; top:100%; left:0; right:0;
            background:var(--bg); border:1px solid var(--border);
            list-style:none; margin:0; padding:0; z-index:100;
            max-height:200px; overflow-y:auto;
          "
            @mouseleave=${() => this.showDropdown = false}
          >
            ${this.suggestions.map(u => html`
              <li @click=${() => this._selectUser(u)} style="
                padding:4px 8px; cursor:pointer; display:flex; justify-content:space-between;
              "
                @mouseover=${(e: Event) => (e.currentTarget as HTMLElement).style.background="var(--highlight-bg)"}
                @mouseout=${(e: Event) => (e.currentTarget as HTMLElement).style.background=""}>
                <span>${u.displayname}</span>
                <span style="color:var(--dim-text)">${u.id}</span>
              </li>
            `)}
          </ul>
        ` : ""}
      </div>
      <button @click=${this._addSelected} ?disabled=${this.adding || !this.query.trim()} style="margin-top:4px;">
        ${this.adding ? "Adding..." : "Add"}
      </button>
    `;
  }

  private _onInput(e: InputEvent) {
    this.query = (e.target as HTMLInputElement).value;
    this.error = "";
    if (this._debounceTimer) clearTimeout(this._debounceTimer);
    if (!this.query.trim()) {
      this.suggestions = [];
      this.showDropdown = false;
      return;
    }
    this._debounceTimer = setTimeout(() => this._search(), this.debounce);
  }

  private async _search() {
    const q = this.query.trim();
    if (!q) return;
    this.loading = true;
    try {
      const resp = await fetch(`/frontend/api/v1/users?q=${encodeURIComponent(q)}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      this.suggestions = await resp.json();
      this.showDropdown = this.suggestions.length > 0;
    } catch (e) {
      console.error("member-picker search error:", e);
      this.suggestions = [];
      this.showDropdown = false;
    } finally {
      this.loading = false;
    }
  }

  private _selectUser(user: UserResult) {
    this.query = user.id;
    this.showDropdown = false;
  }

  private async _addSelected() {
    const userId = this.query.trim();
    if (!userId || !this.groupId) return;
    this.adding = true;
    this.error = "";
    try {
      const resp = await fetch(`/frontend/api/v1/groups/${this.groupId}/members`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id: userId }),
      });
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(text);
      }
      window.location.reload();
    } catch (e) {
      this.error = String(e);
    } finally {
      this.adding = false;
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "member-picker": MemberPicker;
  }
}