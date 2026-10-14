import { html, LitElement } from "lit";
import { customElement, property } from "lit/decorators.js";
import { Ref, createRef, ref } from 'lit/directives/ref.js';

// §18.43: the "Import contacts" dialog — bring contacts in from a file
// exported by another service (Google, Apple, Outlook, …). The file is
// POSTed as the raw request body (the same fetch-the-File shape
// import-calendar-form uses — no multipart), so the destination rides
// in the element's attributes and the server sniffs vCard vs CSV from
// the content. The response is a plain phrase ("Added 12 contacts.
// Skipped 3 …"), shown verbatim.
//
// Two shapes of destination:
//   - a single addressbook — `principal` + `addressbook_id` attributes
//     (the profile page's per-tile form, the per-addressbook Contacts
//     page);
//   - several addressbooks — a `destinations` attribute carrying a
//     JSON list of `{principal, addressbook_id, label}` (askama's
//     `|json` filter escapes it for a single-quoted attribute), and the
//     dialog grows a picker — the aggregate Contacts page shows every
//     writable book, the same picker the new-contact form has.
// `destinations` wins whenever it parses to a non-empty list.
@customElement("import-contacts-form")
export class ImportContactsForm extends LitElement {
  constructor() {
    super()
  }

  protected override createRenderRoot() {
    return this
  }

  @property()
  user: string = ''
  @property()
  principal: string
  @property()
  addressbook_id: string
  @property()
  destinations: string = ''

  dialog: Ref<HTMLDialogElement> = createRef()
  result: Ref<HTMLParagraphElement> = createRef()
  destination: Ref<HTMLSelectElement> = createRef()
  file: File;

  get parsedDestinations(): Array<{ principal: string, addressbook_id: string, label: string }> {
    try {
      let parsed = JSON.parse(this.destinations || '[]')
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  }

  override render() {
    let destinations = this.parsedDestinations
    return html`
      <button @click=${() => { this.result.value?.replaceChildren(); this.dialog.value.showModal() }}>Import contacts</button>
      <dialog ${ref(this.dialog)}>
        <h3>${destinations.length > 1 ? 'Import contacts' : 'Import contacts into this addressbook'}</h3>
        <form @submit=${this.submit}>
          ${destinations.length > 1 ? html`
          <label class="block">
            Import into
            <select ${ref(this.destination)}>
              ${destinations.map((d, i) => html`<option value=${i} ?selected=${i === 0}>${d.label}</option>`)}
            </select>
          </label>
          ` : ''}
          <label>
            file (.vcf or .csv)
            <input type="file" required accept=".vcf,.vcard,.csv,text/vcard,text/csv" @change=${e => this.file = e.target.files[0]} />
          </label>
          <div class="margin-top-m">
            <button type="submit" class="primary">Import</button>
            <button type="button" @click=${() => { this.dialog.value.close(); window.location.reload() }} class="cancel">Close</button>
          </div>
        </form>
        <p class="result" ${ref(this.result)}></p>
        <p class="description">Export vCard (.vcf) from your contacts app for the best results — every field survives. Google and Outlook CSV exports also work. Duplicates are skipped, so nothing is added twice.</p>
      </dialog>
    `
  }

  async submit(e: SubmitEvent) {
    e.preventDefault()
    if (!this.file) {
      alert("Choose a file first")
      return
    }
    // `destinations` wins when it parses to a non-empty list (the
    // picker — or its only entry); the single-destination attributes
    // otherwise.
    let principal = this.principal
    let addressbook_id = this.addressbook_id
    let destinations = this.parsedDestinations
    if (destinations.length > 0) {
      let selected = destinations[0]
      if (this.destination.value && destinations.length > 1) {
        selected = destinations[parseInt(this.destination.value.value, 10) || 0] || destinations[0]
      }
      principal = selected.principal
      addressbook_id = selected.addressbook_id
    }
    let response = await fetch(`/frontend/user/${this.user}/addressbook/import/${principal}/${addressbook_id}`, {
      method: 'POST',
      body: this.file,
    })

    let text = await response.text()
    if (this.result.value) {
      this.result.value.textContent = response.ok
        ? text
        : `Error ${response.status}: ${text}`
    }
    return null
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'import-contacts-form': ImportContactsForm
  }
}