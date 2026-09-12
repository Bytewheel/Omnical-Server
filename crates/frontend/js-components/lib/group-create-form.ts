import { html, LitElement } from "lit";
import { customElement, property } from "lit/decorators.js";
import { Ref, createRef, ref } from "lit/directives/ref.js";

@customElement("group-create-form")
export class GroupCreateForm extends LitElement {
  @property()
  user: string = "";

  @property()
  id: string = "";

  @property()
  displayname: string = "";

  @property()
  members: string = "";

  @property({ type: Boolean })
  calendar: boolean = true;

  @property({ type: Boolean })
  tasks: boolean = true;

  @property({ type: Boolean })
  addressbook: boolean = true;

  @property({ type: Boolean })
  submitting: boolean = false;

  @property()
  error: string = "";

  form: Ref<HTMLFormElement> = createRef();

  protected override createRenderRoot() {
    return this;
  }

  override render() {
    return html`
      <form ${ref(this.form)} @submit=${this.onSubmit}>
        ${this.error ? html`<p class="error">${this.error}</p>` : ""}
        <div>
          <label>
            Group ID
            <input type="text" .value=${this.id} @change=${(e: Event) => this.id = (e.target as HTMLInputElement).value}
              placeholder="my-group" required
              pattern="[a-zA-Z0-9_.@-]+" title="Letters, numbers, dots, underscores, hyphens, @">
          </label>
        </div>
        <div>
          <label>
            Display name
            <input type="text" .value=${this.displayname} @change=${(e: Event) => this.displayname = (e.target as HTMLInputElement).value}
              placeholder="My Group" required>
          </label>
        </div>
        <div>
          <label>
            Members (comma-separated user IDs)
            <input type="text" .value=${this.members} @change=${(e: Event) => this.members = (e.target as HTMLInputElement).value}
              placeholder="alice@example.com, bob@example.com">
          </label>
        </div>
        <fieldset>
          <legend>Collections to create</legend>
          <label><input type="checkbox" .checked=${this.calendar} @change=${(e: Event) => this.calendar = (e.target as HTMLInputElement).checked}> Calendar</label>
          <label><input type="checkbox" .checked=${this.tasks} @change=${(e: Event) => this.tasks = (e.target as HTMLInputElement).checked}> Tasks</label>
          <label><input type="checkbox" .checked=${this.addressbook} @change=${(e: Event) => this.addressbook = (e.target as HTMLInputElement).checked}> Addressbook</label>
        </fieldset>
        <button type="submit" class="primary margin-top-m" ?disabled=${this.submitting}>
          ${this.submitting ? "Creating..." : "Create Group"}
        </button>
      </form>
    `;
  }

  async onSubmit(e: SubmitEvent) {
    e.preventDefault();
    this.error = "";
    this.submitting = true;

    const memberList = this.members
      .split(",")
      .map(s => s.trim())
      .filter(s => s.length > 0);

    try {
      const resp = await fetch("/frontend/api/v1/groups", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: this.id,
          displayname: this.displayname,
          members: memberList,
          collections: {
            calendar: this.calendar,
            tasks: this.tasks,
            addressbook: this.addressbook,
          },
        }),
      });

      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`HTTP ${resp.status}: ${body}`);
      }

      window.location.href = `/frontend/user/${this.user}/groups/${this.id}`;
    } catch (err) {
      this.error = String(err);
    } finally {
      this.submitting = false;
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "group-create-form": GroupCreateForm;
  }
}