import { html, LitElement } from "lit";
import { customElement, property } from "lit/decorators.js";

interface GroupInfo {
  id: string;
  displayname: string;
  owner: boolean;
  member_count: number;
  collections: string[];
}

@customElement("group-list")
export class GroupList extends LitElement {
  @property()
  user: string = "";

  @property({ type: Array })
  groups: GroupInfo[] = [];

  @property({ type: Boolean })
  loading: boolean = true;

  @property()
  error: string = "";

  protected override createRenderRoot() {
    return this;
  }

  override async connectedCallback() {
    super.connectedCallback();
    await this.fetchGroups();
  }

  async fetchGroups() {
    this.loading = true;
    this.error = "";
    try {
      const resp = await fetch("/frontend/api/v1/groups");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      this.groups = await resp.json();
    } catch (e) {
      this.error = String(e);
    } finally {
      this.loading = false;
    }
  }

  override render() {
    if (this.loading) {
      return html`<p>Loading groups&hellip;</p>`;
    }
    if (this.error) {
      return html`<p class="error">Failed to load groups: ${this.error}</p>`;
    }
    if (!this.groups.length) {
      return html`
        <p>You are not a member of any groups yet.</p>
        <div class="section-actions">
          <a href="/frontend/user/${this.user}/groups/new" class="button">New Group</a>
        </div>
      `;
    }

    return html`
      <ul class="collection-list">
        ${this.groups.map(group => html`
          <li class="collection-list-item">
            <a href="/frontend/user/${this.user}/groups/${group.id}"></a>
            <div class="inner">
              <span class="title">
                ${group.displayname}
                ${group.owner ? html`<span class="chip">Owner</span>` : ""}
              </span>
              <span class="description">
                ${group.member_count} member${group.member_count !== 1 ? "s" : ""}
                &middot;
                ${group.collections.length} collection${group.collections.length !== 1 ? "s" : ""}
              </span>
            </div>
          </li>
        `)}
      </ul>
      <div class="section-actions">
        <a href="/frontend/user/${this.user}/groups/new" class="button">New Group</a>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "group-list": GroupList;
  }
}