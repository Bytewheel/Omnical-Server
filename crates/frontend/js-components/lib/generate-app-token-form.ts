import { html, LitElement } from "lit";
import { customElement, property } from "lit/decorators.js";
import { Ref, createRef, ref } from 'lit/directives/ref.js';


@customElement("generate-app-token-form")
export class GenerateAppTokenForm extends LitElement {
  @property()
  user: string = ''
  
  @property()
  token: string = ''

  @property()
  uaApple: boolean = navigator.userAgent.includes('Apple') || navigator.userAgent.includes('macOS') || navigator.userAgent.includes('Macintosh')

  form: Ref<HTMLFormElement> = createRef()

  protected override createRenderRoot() {
    return this
  }

  async onSubmit(e: SubmitEvent) {
    if (e.submitter?.name === 'apple') return;
    e.preventDefault();
    const form = this.form.value
    const data = new URLSearchParams(new FormData(form));
    const res = await fetch(form.action, {
      method: form.method,
      body: data,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    if (!res.ok) {
      alert('Error: ' + await res.text());
      return;
    }

    const token = await res.text();
    this.token = token
    form.reset();
  }

  private async copy(text: string, e: Event) {
    await navigator.clipboard.writeText(text)
    if (e.target instanceof HTMLElement) e.target.textContent = 'Copied!'
  }

  private get caldavUrl(): string {
    return `${location.origin}/caldav`
  }

  private get carddavUrl(): string {
    return `${location.origin}/carddav`
  }

  override render() {
    return html`
      <form method="POST" action=${`/frontend/user/${this.user}/app_token`} @submit=${this.onSubmit} ${ref(this.form)}>
        <input type="text" name="name" placeholder="App name" required />
        <div class="generate-actions">
          <button type="submit" class="primary">Generate</button>
          ${this.uaApple ? html`
            <button type="submit" name="apple" value="true">Apple Configuration Profile (contains token)</button>
          ` : null}
        </div>
      </form>

      <div class="token-result" ?hidden="${!this.token}">
        <p class="token-result-warning">This token will only be shown once. Copy it now and keep it secret.</p>
        <div class="token-result-row">
          <span class="token-label">Username</span>
          <code class="token-value">${this.user}</code>
          <button type="button" @click=${(e: Event) => this.copy(this.user, e)}>Copy</button>
        </div>
        <div class="token-result-row">
          <span class="token-label">Calendar server (CalDAV)</span>
          <code class="token-value">${this.caldavUrl}</code>
          <button type="button" @click=${(e: Event) => this.copy(this.caldavUrl, e)}>Copy</button>
        </div>
        <div class="token-result-row">
          <span class="token-label">Contacts server (CardDAV)</span>
          <code class="token-value">${this.carddavUrl}</code>
          <button type="button" @click=${(e: Event) => this.copy(this.carddavUrl, e)}>Copy</button>
        </div>
        <div class="token-result-row">
          <span class="token-label">App token (password)</span>
          <code class="token-value">${this.token}</code>
          <button type="button" @click=${(e: Event) => this.copy(this.token, e)}>Copy</button>
        </div>
        <p class="token-hint">Enter the username, the server URL for what you want to sync, and this token as the password in your app — full step-by-step help: <a href="#app-token-help">How to use app tokens</a>.</p>
        <button @click=${() => location.reload()}>Done</button>
      </div>
    `
  }
}
